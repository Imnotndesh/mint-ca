package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"mint-ca/internal/storage"
)

type Dialer interface {
	Send(ctx context.Context, server storage.SMTPServer, password string, msg Message) error
}

type SMTPDialer struct{}

func (SMTPDialer) Send(ctx context.Context, server storage.SMTPServer, password string, msg Message) error {
	errCh := make(chan error, 1)
	go func() { errCh <- sendSMTP(server, password, msg) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func sendSMTP(server storage.SMTPServer, password string, msg Message) error {
	addr := net.JoinHostPort(server.Host, strconv.Itoa(server.Port))
	tlsConfig := &tls.Config{ServerName: server.Host, InsecureSkipVerify: server.SkipVerify}

	var conn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	if server.Security == storage.SMTPSecurityTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("notify: dial %s: %w", addr, err)
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, server.Host)
	if err != nil {
		return fmt.Errorf("notify: smtp client: %w", err)
	}
	defer c.Close()

	if server.Security == storage.SMTPSecurityStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("notify: server does not advertise STARTTLS")
		}
		if err := c.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("notify: starttls: %w", err)
		}
	}

	if server.Username != "" {
		if ok, _ := c.Extension("AUTH"); ok {
			auth := smtp.PlainAuth("", server.Username, password, server.Host)
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("notify: auth: %w", err)
			}
		}
	}

	if err := c.Mail(server.FromAddress); err != nil {
		return fmt.Errorf("notify: mail from: %w", err)
	}
	for _, to := range msg.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("notify: rcpt to %s: %w", to, err)
		}
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("notify: data: %w", err)
	}
	if _, err := w.Write(buildMIME(server, msg)); err != nil {
		return fmt.Errorf("notify: write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("notify: close message: %w", err)
	}
	return c.Quit()
}

func buildMIME(server storage.SMTPServer, msg Message) []byte {
	from := server.FromAddress
	if server.FromName != "" {
		from = fmt.Sprintf("%s <%s>", server.FromName, server.FromAddress)
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", strings.Join(msg.To, ", "))
	fmt.Fprintf(&buf, "Subject: %s\r\n", msg.Subject)
	fmt.Fprintf(&buf, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n\r\n")
	buf.WriteString(msg.Body)
	return buf.Bytes()
}
