package main

import (
	"BcAddressCode/base58"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/ripemd160"
)

const VERSION  = 0X00

func main() {
	address := GetAddress()
	fmt.Println(address)
	isValid := CheckAdd(address)
	fmt.Println(isValid)
}

//产生私钥
func GenerateKey(curve elliptic.Curve)(*ecdsa.PrivateKey,error)  {
	/*curve := elliptic.P256()*/
	return ecdsa.GenerateKey(curve, rand.Reader)
	/*if err != nil {
		return nil, err
	}
	return pri, nil*/
}

//非压缩格式公钥
func GetUnCompressPub(curve elliptic.Curve,pri *ecdsa.PrivateKey) []byte {
	return elliptic.Marshal(curve,pri.X,pri.Y)
}

//sha256 哈希
func Sha256Hash(data []byte) ([]byte) {
	sha256Hash := sha256.New()
	sha256Hash.Write(data)
	return sha256Hash.Sum(nil)
}

//ripemd160 哈希
func Ripemd160Hash(msg []byte) []byte {
	ripemd := ripemd160.New()
	ripemd.Write(msg)
	return ripemd.Sum(nil)
}

func GetAddress() string {
	curve := elliptic.P256()

	pri,_:=GenerateKey(curve)
	pub:= GetUnCompressPub(curve,pri)

	//1.sha256 公钥计算
	hash256 := Sha256Hash(pub)
	ripemd160:= Ripemd160Hash(hash256)

	//version  添加版本号作为前缀
	//versionRipemd := append([]byte{0x00},ripemd160...)
	versionRipemd := append([]byte{VERSION},ripemd160...)

	//double hash 计算校验位
	hash1 := Sha256Hash(versionRipemd)
	hash2 := Sha256Hash(hash1)

	//截取前四位作为校验位
	check := hash2[:4]
	//与versionRipemd进行拼接
	add := append(versionRipemd,check...)

	//base58编码，返回
	return base58.Encode(add)

}

//校验给定的比特币的地址是否有效
func CheckAdd(add string) bool {
	//1.反编码
	deAddBytes := base58.Decode(add)
	//2.截取校验位
	deCheck := deAddBytes[:len(deAddBytes) - 4]
	//3.计算校验位
	//a.获取反编码去除后四位的内容
	versionRipemd160:=deAddBytes[:len(deAddBytes) - 4]
	//b.双hash
	sha256Hash := sha256.New()
	sha256Hash.Write(versionRipemd160)
	hash1 := sha256Hash.Sum(nil)

	sha256Hash.Reset()
	sha256Hash.Write(hash1)
	hash2 := sha256Hash.Sum(nil)
	//c.截取前四位作为校验位
	check := hash2[:4]
	//比较
	/*isValid := bytes.Compare(deCheck,check)
	if isValid == 0{
		fmt.Println("有效")
		return true
	}*/
	return bytes.Compare(deCheck,check) == 0
	/*if string(deCheck) == string(check){
		fmt.Println("比特币地址有效")
	}else if string(deCheck) != string(check){
		fmt.Println("比特币地址无效")
	}
	return false*/
}