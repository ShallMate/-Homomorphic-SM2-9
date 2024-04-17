# -Homomorphic-SM2-9

加法同态的SM2加解密函数是sm2/sm2enc.go 里的LgwHEnc与LgwHDec


加法同态的SM9加解密函数是sm9/sm9.go 里的LgwHEnc与LgwHDec


sm2enc.go与sm9.go里的init.go函数用于生成BSGS算法的预计算表


使用不顺利可联系: gw_ling@sjtu.edu.cn,欢迎一起交流.


此代码是基于[xlcetc/cryptogm](https://github.com/xlcetc/cryptogm)的二次开发,在这里表达感谢！

## 例子：测试同态SM2
```
cd $GOPATH/src/github.com
git clone https://github.com/ShallMate/-Homomorphic-SM2-9.git
mv -- -Homomorphic-SM2-9 xlcetc
cd xlcetc
go run testgm.go
```

## Paper

http://www.jcr.cacrnet.org.cn/CN/10.13868/j.cnki.jcr.000532