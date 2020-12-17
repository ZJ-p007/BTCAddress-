package tool

import (
	"BcAddressCode/base58"
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/ripemd160"
)

func main1() {
	//fmt.Println("Hello Word")
	//1.生成公私钥
	curve := elliptic.P256()
	//椭圆曲线方程
	//pri, err := ecdsa.GenerateKey(curve, rand.Reader)
	//x,y可以组成公钥
	_, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	//将x,y组成公钥转换为[]byte类型
	//公钥;x + y
	/*pubKey := append(x.Bytes(), y.Bytes()...)
	pubKey = append([]byte{04},pubKey...)*/

	//系统api
	pubKey:=elliptic.Marshal(curve,x,y)
	//x坐标32字节，y32字节
	fmt.Println("非压缩格式公钥:",pubKey)
	fmt.Println("压缩格式公钥长度:",len(pubKey))

	//第二步
	sha256Hash := sha256.New()
	sha256Hash.Write(pubKey)
	pubHash256 := sha256Hash.Sum(nil)
	//ripemd160
	ripemd := ripemd160.New()
	ripemd.Write(pubHash256)
	pubripemd160 := ripemd.Sum(nil)

	//第三步：添加版本号前缀
	versionPubRipemd160 := append([]byte{0x00}, pubripemd160...)

	//第四步:计算校验位
	//1.
	sha256Hash.Reset() //重置
	sha256Hash.Write(versionPubRipemd160)
	hsh1 := sha256Hash.Sum(nil)

	//2.sha256
	sha256Hash.Reset() //重置
	sha256Hash.Write(hsh1)
	hash2 := sha256Hash.Sum(nil)

	//3.取前四个字节
	//如何截取[]byte的前四个内容
	check := hash2[0:4]

	//第五步，拼接校验位得到地址
	addByes := append(versionPubRipemd160, check...)
	fmt.Println("地址:", addByes)

	//第六步
	address := base58.Encode(addByes)
	fmt.Println("生成的新的比特币地址:", address)

	//-------------校验---------------//
	/**
	1.把地址base58解码成字节数组
	2.把数组分成两个字节数组，字节数组（一）是后4字节数组，字节数组（二）是减去后4字节的数组
	3.把字节数组（二）两次Sha256 Hash
	4.取字节数组（二）hash后的前4位，跟字节数组（一）比较。如果相同校验通过。
	5.校验通过的解码字节数组取第一个字节（0xff），得到版本号
	6.检验版本号的合法性（根据主网参数校验）
	*/

	//base58解码
	address1 := base58.Decode(address)
	//fmt.Println("base58解码:",address1)
	check1 := address1[0:21]
	//取解码后的后四位，作为校验位
	check2 := address1[21:25]
	//fmt.Println("解码后的后四位:",check2)
	//fmt.Println("截取后:",check1)

	sha256Hash.Reset()
	sha256Hash.Write(check1)
	hash3 := sha256Hash.Sum(nil)

	sha256Hash.Reset()
	sha256Hash.Write(hash3)
	hash4 := sha256Hash.Sum(nil)

	check3 := hash4[0:4]

	if string(check3) == string(check2) {
		fmt.Println("比特币地址有效" )
	} else if string(check3) != string(check2) {
		fmt.Println("比特币地址无效")
	}
}


