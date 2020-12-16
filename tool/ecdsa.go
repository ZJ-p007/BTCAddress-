package tool

import (
	"BcAddressCode/base58"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/ripemd160"
)

//生成椭圆曲线加密算法中的私钥
func GenerateECDSAKey()(*ecdsa.PrivateKey,error){
	curve:= elliptic.P256()
	pri,err := ecdsa.GenerateKey(curve,rand.Reader)
	if err != nil{
		return nil,err
	}
	return pri,nil

	//将pri转换为[]byte类型
	pubKey := append(pri.X.Bytes())

	//将pubKey进行sha256计算
	sha256Hash := sha256.New()
	sha256Hash.Write(pubKey)
	pubHash256 :=sha256Hash.Sum(nil)

	//进行ripemd160
	ripemd :=ripemd160.New()
	ripemd.Write(pubHash256)
	pubripemd160 :=ripemd.Sum(nil)

	//添加版本号前缀
	versionPubRipemd160 :=append([]byte{0x00}, pubripemd160...)

	//第四步:计算校验位
	sha256Hash.Reset()//重置
	sha256Hash.Write(versionPubRipemd160)
	hsh1 := sha256Hash.Sum(nil)

	//2.sha256
	sha256Hash.Reset()//重置
	sha256Hash.Write(hsh1)
	hash2 := sha256Hash.Sum(nil)

	//3.取前四个字节
	//如何截取[]byte的前四个内容
	check :=hash2[0:4]

	//第五步，拼接校验位得到地址
	addByes := append(versionPubRipemd160,check...)
	fmt.Println("地址:",addByes)

	//第六步
	address := base58.Encode(addByes)
	fmt.Println("生成的新的比特币地址:",address)

	return nil,err

}
