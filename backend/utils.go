package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/argon2"
)

func errorJson(err string) string {
	json, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: err})
	return string(json)
}

func handleInternalServerError(w http.ResponseWriter, err error) {
	log.Println("Internal Server Error!", err)
	http.Error(w, errorJson("Internal Server Error!"), http.StatusInternalServerError)
}

func wsInternalError(c *websocket.Conn, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	log.Println("Internal Server Error!", err)
	_ = c.Write(ctx, websocket.MessageText, []byte(errorJson("Internal Server Error!")))
	_ = c.Close(websocket.StatusInternalError, "Internal Server Error!")
}

func wsError(c *websocket.Conn, err string, code websocket.StatusCode) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	_ = c.Write(ctx, websocket.MessageText, []byte(errorJson(err)))
	_ = c.Close(code, err)
}

func GetTokenFromHTTP(r *http.Request) string {
	token := r.Header.Get("Authorization")
	if cookie, err := r.Cookie("token"); err == nil {
		token = cookie.Value
	}
	return token
}

// GenerateSalt returns a 16-character salt readable in UTF-8 format as well.
func GenerateSalt() []byte {
	saltBytes := make([]byte, 12)
	_, _ = rand.Read(saltBytes)
	salt := base64.RawStdEncoding.EncodeToString(saltBytes)
	return []byte(salt)
}

func HashPassword(password string, salt []byte) string {
	params := "$argon2id$v=19$m=51200,t=1,p=4$" // Currently fixed only.
	key := argon2.IDKey([]byte(password), salt, 1, 51200, 4, 32)
	return params + base64.RawStdEncoding.EncodeToString(salt) +
		"$" + base64.RawStdEncoding.EncodeToString(key)
}

func ComparePassword(password string, hash string) bool {
	encodeSplit := strings.Split(hash, "$")
	salt, _ := base64.RawStdEncoding.DecodeString(encodeSplit[len(encodeSplit)-2])
	key := argon2.IDKey([]byte(password), salt, 1, 51200, 4, 32)
	hashValue := encodeSplit[len(encodeSplit)-1]
	return hashValue == base64.RawStdEncoding.EncodeToString(key)
}

func IsEmailConfigured() bool {
	return config.EmailSettings.Username != "" &&
		config.EmailSettings.Password != "" &&
		config.EmailSettings.Host != ""
}

func SendHTMLEmail(email string, subject string, body string) error {
	auth := smtp.PlainAuth(
		config.EmailSettings.Identity,
		config.EmailSettings.Username,
		config.EmailSettings.Password,
		config.EmailSettings.Host)
	from := config.EmailSettings.Identity
	if from == "" {
		from = config.EmailSettings.Username
	}
	host := config.EmailSettings.Host
	if !strings.Contains(host, ":") {
		host += ":587"
	}
	msg := []byte("To: " + email + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n" +
		"\r\n" +
		strings.ReplaceAll(body, "\n", "\r\n") + "\r\n")
	return smtp.SendMail(host, auth, from, []string{email}, msg)
}

func init() {
	// For the future, animated AVIF = ????ftypavis
	image.RegisterFormat("avif", "????ftypavif", DecodeAVIF, func(reader io.Reader) (image.Config, error) {
		img, err := DecodeAVIF(reader)
		if err != nil {
			return image.Config{}, err
		}
		return image.Config{ColorModel: img.ColorModel(), Width: img.Bounds().Dx(), Height: img.Bounds().Dy()}, nil
	})
}

func DecodeAVIF(reader io.Reader) (image.Image, error) {
	// Create a temporary file containing the AVIF data
	file, err := os.CreateTemp(os.TempDir(), "concinnity-*.avif")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	if _, err := io.Copy(file, reader); err != nil {
		return nil, err
	} else if err := file.Close(); err != nil {
		return nil, err
	}

	// Decode to PNG and read back the data
	defer os.Remove(file.Name() + ".png")
	if err := exec.Command("avifdec", "--png-compress", "0", file.Name(), file.Name()+".png").Run(); err != nil {
		return nil, err
	}
	file, err = os.Open(file.Name() + ".png")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	img, err := png.Decode(file)
	if err != nil {
		return nil, err
	}
	return img, nil
}

func EncodeAVIF(image image.Image, quality int) ([]byte, error) {
	// Create a temporary file to encode the image to AVIF using avifenc
	file, err := os.CreateTemp(os.TempDir(), "concinnity-*.avif")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	// Note: --stdin was added with libavif 1.4.0, so we can avoid creating a temporary PNG file.
	// Note: -a c:tune=iq is default with libavif 1.4.0 in certain cases
	var cmd *exec.Cmd
	if quality == 100 {
		cmd = exec.Command("avifenc", "-y", "444", "-d", "10", "-a", "c:tune=iq", "-l", "--stdin", "--input-format", "png", file.Name())
	} else {
		cmd = exec.Command("avifenc", "-y", "444", "-d", "10", "-a", "c:tune=iq", "-q", strconv.Itoa(quality), "--stdin", "--input-format", "png", file.Name())
	}
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	writer, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	encoder := png.Encoder{CompressionLevel: png.NoCompression}
	if err := encoder.Encode(writer, image); err != nil {
		writer.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return nil, err
	} else if err := writer.Close(); err != nil {
		return nil, err
	}
	if err = cmd.Wait(); err != nil {
		log.Printf("avifenc error: %v, output: %s", err, b.String())
		return nil, err
	} else {
		//log.Printf("avifenc output: %s", b.String())
	}
	data, err := os.ReadFile(file.Name())
	if err != nil {
		return nil, err
	}
	return data, nil
}
