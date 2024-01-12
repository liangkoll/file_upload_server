package main

import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// 创建一个WaitGroup
var wg sync.WaitGroup

func generateSelfSignedCert() (tls.Certificate, error) {
	privKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 自签名证书有效期1年

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := crand.Int(crand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "127.0.0.1", "::1", "10.13.132.13"},
	}

	certBytes, err := x509.CreateCertificate(crand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	tlsCert, err := tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse X509 key pair: %w", err)
	}

	return tlsCert, nil
}
func setupRouter() *gin.Engine {
	r := gin.Default()
	// 设置静态文件目录
	r.Static("/static", "./static")

	// 设置HTML模板目录
	r.LoadHTMLGlob("templates/*")

	// 文件上传页面
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	// 文件上传接口
	r.POST("/upload", func(c *gin.Context) {
		form, err := c.MultipartForm()
		if err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("上传文件失败: %s", err.Error()))
			return
		}
		files := form.File["files"]
		for _, file := range files {
			// 创建目标文件
			// // 创建目标文件
			filename := filepath.Base(file.Filename)
			dst := fmt.Sprintf("./uploads/%s", filename)
			out, err := os.Create(dst)
			// out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE, 0666)
			if err != nil {
				c.String(http.StatusInternalServerError, fmt.Sprintf("打开文件失败: %s", err.Error()))
				return
			}
			// defer out.Close()

			// 打开上传的文件
			src, err := file.Open()
			if err != nil {
				c.String(http.StatusInternalServerError, fmt.Sprintf("打开文件失败: %s", err.Error()))
				return
			}
			defer src.Close()
			// 复制文件内容到目标文件
			_, err = io.Copy(out, src)
			if err != nil {
				c.String(http.StatusInternalServerError, fmt.Sprintf("复制文件失败: %s", err.Error()))
				return
			}
			// 获取文件大小
			fileSize := file.Size

			// 创建一个管道用于传递进度
			progressCh := make(chan int)
			// 启动一个 goroutine 处理文件上传，并更新进度
			go func() {
				defer close(progressCh)
				defer wg.Done()
				defer out.Close()
				// 创建一个缓冲区
				buffer := make([]byte, 1024)
				// 记录已写入的字节数
				var written int64
				// 读取文件内容并复制到目标文件
				for {
					n, err := src.Read(buffer)
					if err != nil && err != io.EOF {
						fmt.Println("读取文件失败: ", err)
						return
					}
					if n == 0 {
						break
					}

					// 写入目标文件
					_, err = out.Write(buffer[:n])
					if err != nil {
						fmt.Println("写入文件失败: ", err)
						return
					}
					// 更新已写入的字节数
					written += int64(n)
					// 计算上传进度
					progress := int(float64(written) / float64(fileSize) * 100)

					// 发送进度到管道
					progressCh <- progress
				}
			}()
			wg.Add(1)
			wg.Wait()
			// 等待文件上传完成
			// go func() {
			// 	for range progressCh {
			// 		// 在这里可以处理上传进度，例如发送给客户端或记录日志
			// 	}
			// }()
		}
		c.String(http.StatusOK, "文件上传成功")
		// c.String(http.StatusOK, fmt.Sprintf("文件 %s 上传成功", filename))
	})

	// 文件列表接口
	r.GET("/list", func(c *gin.Context) {
		files, err := filepath.Glob("./uploads/*")
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("获取文件列表失败: %s", err.Error()))
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"files": files,
		})
	})
	// 文件下载接口
	r.GET("/download/:filename", func(c *gin.Context) {
		filename := c.Param("filename")
		filepath := fmt.Sprintf("./uploads/%s", filename)
		_, err := os.Stat(filepath)
		if os.IsNotExist(err) {
			c.String(http.StatusNotFound, fmt.Sprintf("文件 %s 不存在", filename))
			return
		}
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Header("Content-Type", "application/octet-stream")
		c.File(filepath)
	})
	// 文件删除接口
	r.DELETE("/delete/:filename", func(c *gin.Context) {
		filename := c.Param("filename")
		filepath := fmt.Sprintf("./uploads/%s", filename)
		err := os.Remove(filepath)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("删除文件失败: %s", err.Error()))
			return
		}
		c.String(http.StatusOK, fmt.Sprintf("文件 %s 删除成功", filename))
	})
	// WebSocket接口
	r.GET("/ws", func(c *gin.Context) {
		_, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			fmt.Println("Failed to set websocket upgrade: ", err)
			return
		}
	})

	// r.Run(":8080")
	return r
}
func main() {
	router := setupRouter()
	// 生成自签名证书
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		panic(err)
	}
	// 启用HTTPS服务
	srv := &http.Server{
		Addr:      ":8080",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}},
		Handler:   router,
	}

	log.Println("[GIN-debug] Listening and serving HTTPS on :8080")
	err = srv.ListenAndServeTLS("", "")
	if err != nil && err != http.ErrServerClosed {
		log.Fatal("ListenAndServeTLS: ", err)
	}
}
