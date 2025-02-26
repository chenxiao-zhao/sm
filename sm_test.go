/*
 * @Author: cxzhao 1037089219@qq.com
 * @Date: 2023-12-22 16:50:19
 * @LastEditors: cxzhao 1037089219@qq.com
 * @LastEditTime: 2024-01-06 15:57:45
 * @FilePath: \did_miniprogram_api\test\cli_test.go
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
 package sm

 import (
	 "fmt"
	 "testing"
 )
 
 func TestSm3Hex(t *testing.T) {
	 var src = "536"
	 hashHex := Sm3Hash(src)
	 fmt.Printf("cipher text:%s\n", hashHex)
 }
 
 func TestSm2Decrypt_C1C2C3(t *testing.T) {
	 pubStr := "f5f1b7955864b963a566a2efb559d5431d7a4b0151f6bec518f3f1d11463b39c829059cdb21599da0cf1175e8fdbde1e35a6e84960b3693b5bc9464e6164ee60"
	 msg := "142536"
	 cipherText, err := Sm2PublicKeyEncrypt_C1C3C2(pubStr, msg)
 
	 if err != nil {
		 t.Error(err.Error())
		 return
	 }
	 fmt.Printf("cipher text:%s\n", cipherText)
 }
 func TestSm2Encrypt_C1C2C3(t *testing.T) {
	 // pubStr := "f5f1b7955864b963a566a2efb559d5431d7a4b0151f6bec518f3f1d11463b39c829059cdb21599da0cf1175e8fdbde1e35a6e84960b3693b5bc9464e6164ee60"
	 // msg := "142536"
	 // cipherText1, err := Sm2PublicKeyEncrypt_C1C3C2(pubStr, msg)
	 // if err != nil {
	 // 	t.Error(err.Error())
	 // 	return
	 // }
	 cipherText1 := "043a3d212c31b7f3bb31938791f864128e7a773e99aeabda6a6d4d2fc1a1f49b5f8e674e0df1caac00742448817181184932ff43e303d5ffb2e3116af3a23db60861cac5b9b9094473e02a1b965b5b9e7b79e4ef06da7273036c1a1b6291662b8488e6a0f83b86"
	 PriStr := "93f3b7bb27feab401ee081cda6b83ad0a78403a58871fafbadfe531c1af2a56a"
	 //msg := "044dfc3ac17df1c241c3fa7b5fcf85536f7e920cb2495291d90dffbc9980090e2ac1f333bfc654fcf00487444c87df3afad1957fc2df9e1b405c9c1b21e1ab88a907f151b5fe4a636dc62766e58535ffa94b9bf57557a6ac595076a867e67d3a053cfb646e4478"
	 cipherText, err := Sm2PrivateKeyDecrypt_C1C3C2(PriStr, cipherText1)
 
	 if err != nil {
		 t.Error(err.Error())
		 return
	 }
	 fmt.Printf("cipher text:%s\n", cipherText)
 }
 
 func TestSmSign(t *testing.T) {
	 a, err := Sm2PrivateKeySign("554885bf5bd1a016d82b5cfa76ea0b1377e189bb960fba47cfa6b926a7560077", "142536")
	 if err != nil {
		 fmt.Printf("get token err: %s \n", err)
		 return
	 }
	 fmt.Printf("token expire time: %s \n", a)
 }
 
 func TestSmVerify(t *testing.T) {
	 a, err := Sm2PublicKeyVerify("A87BF5C31C6676F9A32CD960C00614E5A68CFBBBC55564019FE2A87C820AD14E|24988A8B5E8A6FE64E7C75C6E86CBF1FF81826BF7E2980BA4777ACE76CF8980C|DAF322EF2717F7D085A94330F32134799F312D03DFCBE73F9459B88127D61B86|F77A315A45C0F52B676F9549C93F8FCC375617D241FDB7617108675B4CC6BD8E|50E10950B20836E74C78393EA5CD3A524CD21947AAB2A3D257458B6CB0959039|B2B99D67968CC89F93D0FED2B8B717B5093A5E17EED375D1ADA38EFED5F8F8E3|4E1D88FE1B8D5FFA08A84CAF037D4E8E49FF59DADECDA9E55133A87B52BAF3D8|06D47B6F2F121E85160D1D8072E58843DE1EED164ED526C3B56B22C2B47324A0", "3046022100f6199d3eeca85a9296f91a4dd3286a62c0a8c21a9dfa1aa5de700819f24d7d62022100f8183f3eddc0896b084cb9a8faf7022b78330af11f0e323ad2c35a0bd661c994", "a4d11cf484066d9919dfa3560f8b61e364839a6e0625a7d9783191f0dd63df9a5a868aab1048b3134f918faa6aa16eec422b8bbb5f05e4237e8781f2f9484941")
	 if err != nil {
		 fmt.Printf("get token err: %s \n", err)
		 return
	 }
	 fmt.Printf("token expire time: %v \n", a)
 }
 