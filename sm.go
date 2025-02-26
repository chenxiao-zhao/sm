package sm

// 参考： https://blog.csdn.net/weixin_42704356/article/details/129669531
import (
	"encoding/hex"
	"fmt"
	"sm/gm/sm2"
	"sm/gm/sm3"
	"strings"
)

// publicKey 128 位16进制公钥
func Sm2PublicKeyEncrypt_C1C3C2(publicKey, msg string) (cipherContent string, err error) {
	publicKeyByte, err := hex.DecodeString(publicKey)
	if err != nil {
		fmt.Printf("publicKey hex decode err: %s", err)
		return
	}
	public, err := sm2.RawBytesToPublicKey(publicKeyByte)
	if err != nil {
		fmt.Printf("public key loading exception,err: %s", err)
		return
	}

	cipherText, err := sm2.Encrypt(public, []byte(msg), sm2.C1C3C2)
	if err != nil {
		fmt.Printf("sm public key encrypt err: %s", err)
		return
	}
	fmt.Printf("cipherText text:%v", cipherText)
	cipherContent = hex.EncodeToString(cipherText)
	fmt.Printf("cipher text:%s", cipherContent)
	return
}

func Sm2PrivateKeyDecrypt_C1C3C2(privateKey, msg string) (cipherContent string, err error) {
	// 解码hex私钥
	privateKeyByte, err := hex.DecodeString(privateKey)
	if err != nil {
		fmt.Printf("privateKey hex decode err: %s", err)
		return
	}
	// 转成go版的私钥
	private, err := sm2.RawBytesToPrivateKey(privateKeyByte)
	if err != nil {
		fmt.Printf("private key loading exception,err:%s", err)
	}

	msgByte, err := hex.DecodeString(msg)
	if err != nil {
		fmt.Printf("publicKey hex decode err: %s", err)
		return
	}

	cipherText, err := sm2.Decrypt(private, msgByte, sm2.C1C3C2)
	if err != nil {
		fmt.Printf("sm public key encrypt err: %s", err)
		return
	}
	//cipherContent = hex.EncodeToString(cipherText)
	cipherContent = string(cipherText)

	fmt.Printf("cipher text:%s", cipherContent)
	return
}

func Sm3Hash(msg string) string {
	hash := sm3.Sum([]byte(msg))
	hashHex := hex.EncodeToString(hash[:])
	upper := strings.ToUpper(hashHex)
	return upper
}

func Sm2PrivateKeySign(privateKey, msg string) (signString string, err error) {
	// 解码hex私钥
	privateKeyByte, err := hex.DecodeString(privateKey)
	if err != nil {
		fmt.Printf("privateKey hex decode err: %s", err)
		return
	}
	// 转成go版的私钥
	private, err := sm2.RawBytesToPrivateKey(privateKeyByte)
	if err != nil {
		fmt.Printf("private key loading exception,err:%s", err)
	}
	signature, err := sm2.Sign(private, []byte("1234567812345678"), []byte(msg))
	if err != nil {
		fmt.Printf("sign err:%s", err)
	}
	// 转 base64
	//sign := base64.StdEncoding.EncodeToString(signature)
	signString = hex.EncodeToString(signature)
	return
}

func Sm2PublicKeyVerify(data, sign, publicKey string) (is bool, err error) {
	publicKeyByte, err := hex.DecodeString(publicKey)
	if err != nil {
		fmt.Printf("publicKey hex decode err: %s", err)
		return
	}
	public, err := sm2.RawBytesToPublicKey(publicKeyByte)
	if err != nil {
		fmt.Printf("public key loading exception,err: %s", err)
		return
	}
	signByte, err := hex.DecodeString(sign)
	if err != nil {
		fmt.Printf("sign DecodeString err:%s", err)
	}
	return sm2.Verify(public, []byte("1234567812345678"), []byte(data), signByte), nil
}
