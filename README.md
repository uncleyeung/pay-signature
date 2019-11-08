<p align="center">
  <a href="https://github.com/uncleyeung">
   <img alt="Uncle-Yeong-Logo" src="https://raw.githubusercontent.com/uncleyeung/uncleyeung.github.io/master/web/img/logo1.jpg">
  </a>
</p>

<p align="center">
  为简化开发工作、提高生产率而生
</p>

<p align="center">
  
  <a href="https://github.com/996icu/996.ICU/blob/master/LICENSE">
    <img alt="996icu" src="https://img.shields.io/badge/license-NPL%20(The%20996%20Prohibited%20License)-blue.svg">
  </a>

  <a href="https://www.apache.org/licenses/LICENSE-2.0">
    <img alt="code style" src="https://img.shields.io/badge/license-Apache%202-4EB1BA.svg?style=flat-square">
  </a>
</p>

# uncleyeung's Repo For Cydia
> * Source: https://github.com/uncleyeung/uncleyeung.github.io/
> * Twitter: https://twitter.com/_uncleyeung
> * Tumblr: https://www.tumblr.com/blog/uncleyeung
# 支付业务签名之个人答疑解惑
###先上代码再说，前请提要
```java
class PaySignature{
    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException {
    
                //待签名字符串
                String signStr = "test";
                //私钥-》Pkcs8
                String privatePkcs8Key = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAMKQxUl7daDCLeeS6UvbnyGPUXoSimKLs8bQxR2kWHalU+Foa5QdvLB9gz33vA3eSfNOMoe0tMREbiU3b7oBU2PaRh1Gm2CuNZRNlwhBT1E/0FKbq4spEJCQIgEK2oSou1FrtqteZxOWwoBZS3ty22caQGMmVO3cxm2MQMZpxTYJAgMBAAECgYEAqrkhhAMDChaY9RQiBeAmV+pMEhNmvmXbT98st3/X5/PWEHnxu7wEL9FScfOJXZnpxcad7BoSbA2noJxuOwaixfm87HQphUvVb/e1ewSiK4Iqq0OXIqTN5rtj9r2rvMgZT0LgQombq8FcRbNOZkc/1NlA2Y6F+aP5zNED3UKSpAECQQDfUju/M0MQaqZtr6137hsxk0bdAqPa4aIxTIZUfPblK+GDceriWp6M2fEAbQRco0p0PKTVJA7JywZhjPH7rVvJAkEA3wlUFZpy+fCXb2TIYyCpJgugIwtGwBUT4jo610LuNyKaxsRikB/8NvfwuchDDEF6VZdk5N12oyPJDmeEct2oQQJAPl16rfSk3+rIu4z6BqoKEhgtC/92vuOQJfBW+zVCxdExU0H29GuWJ4OdmB7Zvv0jB77/0T4WmygFiiyQT1akcQJBAI2rQzmlrTqNU+NxxMcSS97aq5EW7I291a9xBUcOQHnNBTsUKvcZGf9gZgvb5Jq4TJhpXbDx6xWc+Wyo3DyKBwECQQCH6Yl/g91Ia2A0OWXInNj+apg3AlEOXFduUwldby7iZxUfyNqG3hwP5jINFrw2jXy8vnVEsSLal3Usbq2lcjF7";
                //私钥
                String privateKey ="MIICXgIBAAKBgQDCkMVJe3Wgwi3nkulL258hj1F6Eopii7PG0MUdpFh2pVPhaGuUHbywfYM997wN3knzTjKHtLTERG4lN2+6AVNj2kYdRptgrjWUTZcIQU9RP9BSm6uLKRCQkCIBCtqEqLtRa7arXmcTlsKAWUt7cttnGkBjJlTt3MZtjEDGacU2CQIDAQABAoGBAKq5IYQDAwoWmPUUIgXgJlfqTBITZr5l20/fLLd/1+fz1hB58bu8BC/RUnHziV2Z6cXGnewaEmwNp6CcbjsGosX5vOx0KYVL1W/3tXsEoiuCKqtDlyKkzea7Y/a9q7zIGU9C4EKJm6vBXEWzTmZHP9TZQNmOhfmj+czRA91CkqQBAkEA31I7vzNDEGqmba+td+4bMZNG3QKj2uGiMUyGVHz25Svhg3Hq4lqejNnxAG0EXKNKdDyk1SQOycsGYYzx+61byQJBAN8JVBWacvnwl29kyGMgqSYLoCMLRsAVE+I6OtdC7jcimsbEYpAf/Db38LnIQwxBelWXZOTddqMjyQ5nhHLdqEECQD5deq30pN/qyLuM+gaqChIYLQv/dr7jkCXwVvs1QsXRMVNB9vRrlieDnZge2b79Iwe+/9E+FpsoBYoskE9WpHECQQCNq0M5pa06jVPjccTHEkve2quRFuyNvdWvcQVHDkB5zQU7FCr3GRn/YGYL2+SauEyYaV2w8esVnPlsqNw8igcBAkEAh+mJf4PdSGtgNDllyJzY/mqYNwJRDlxXblMJXW8u4mcVH8jaht4cD+YyDRa8No18vL51RLEi2pd1LG6tpXIxew==";
                //获得数字摘要（加签）
                String sign = RSA.sign(signStr, privatePkcs8Key, Constant.DEFAULT_CHARSET);
                //公钥
                String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCkMVJe3Wgwi3nkulL258hj1F6Eopii7PG0MUdpFh2pVPhaGuUHbywfYM997wN3knzTjKHtLTERG4lN2+6AVNj2kYdRptgrjWUTZcIQU9RP9BSm6uLKRCQkCIBCtqEqLtRa7arXmcTlsKAWUt7cttnGkBjJlTt3MZtjEDGacU2CQIDAQAB";
                //验签
                boolean verify = RSA.verify(signStr, sign, publicKey, Constant.DEFAULT_CHARSET);
                System.out.println("verify = " + verify);
                //输出结果为true
                
    }
}
```
-----
####1.什么是非对称性加密？什么是对称加密？
 + 1976年以前，所有的加密方法都是同一种模式：
   
 　　（1）甲方选择某一种加密规则，对信息进行加密；
 
 　　（2）乙方使用同一种规则，对信息进行解密。
 
   由于加密和解密使用同样规则（简称"密钥"），这被称为"对称加密算法"（Symmetric-key algorithm）。
 
   这种加密模式有一个最大弱点：甲方必须把加密规则告诉乙方，否则无法解密。保存和传递密钥，就成了最头疼的问题。
 
 + 1976年，两位美国计算机学家Whitfield Diffie 和 Martin Hellman，提出了一种崭新构思，可以在不直接传递密钥的情况下，完成解密。这被称为"Diffie-Hellman密钥交换算法"。这个算法启发了其他科学家。人们认识到，加密和解密可以使用不同的规则，只要这两种规则之间存在某种对应关系即可，这样就避免了直接传递密钥。
   
   这种新的加密模式被称为"非对称加密算法"。
   
   　　（1）乙方生成两把密钥（公钥和私钥）。公钥是公开的，任何人都可以获得，私钥则是保密的。
   
   　　（2）甲方获取乙方的公钥，然后用它对信息加密。
   
   　　（3）乙方得到加密后的信息，用私钥解密。
   
   如果公钥加密的信息只有私钥解得开，那么只要私钥不泄漏，通信就是安全的。
 + [RSA算法原理详见](http://www.ruanyifeng.com/blog/2013/06/rsa_algorithm_part_one.html)
-----
####2.什么是加签验签？来自项目实践。
+ 一般出现在外部a调用内部b服务，怎么验证其合法性？其中一个就是公私钥解决方法

+ a生成私钥公钥，将公钥交给b，当a调用b的服务时，用请求的dto生成待加签字符串，使用私钥对该字符串加签，生成数字摘要一并且访问b服务

+ b服务请求，得到请求dto/数字摘要，此时b按照约定好的规则将dto生成待签名字符串，同传来的数字摘要，和a给b的公钥验证合法性，合法即通过

+ 以上请求加签验签，以下响应加签验签

+ 在响应时b用响应dto生成待签名字符串，用私钥加签生成逆向数字摘要，一并响应给a

+ a服务得到响应，对dto生成待签名字符串，使用b颁发的公钥，和响应来的数字摘要验证签名，合法即通过

+ 为什么要这么做？双方都是服务器你请求的数据我不信，我要验证，我响应的数据你也不信，也要验证。

-----
####2.扯了这么多怎么生成公私钥？举例其中一种（本人linux自带支持openssl，win[自行搜索](http://www.google.com)）
+ 生成私钥：openssl genrsa -out rsa_private_key.pem 1024

+ 根据私钥生成公钥：openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

+ 根据密钥生成pkcs8密钥：openssl pkcs8 -topk8 -nocrypt -inform PEM -in rsa_private_key.pem -outform PEM

+ 三个文件生成目录~/rsa_private_key.pem ~/rsa_public_key.pem

+ vim rsa_private_key.pem/rsa_public_key.pem 替换换行符号（%s/\n//g）

+ [参见](https://www.jianshu.com/p/a025e6fb0c63)

-----
####3.可忽略
##### 验证签名规则：
+ BaseRequestDTO 转换成 map 
+ 取出不是sign/signData/ipAddress/class/signType key（BaseRequestDTO的成员变量名）封装到LinkedList
+ 对LinkedList<string>按照字母排序
+ 迭代LinkedList<string>取出key，使用CaseFormat.LOWER_CAMEL方法将key按照规则(keyName==>key_name)生成新的key
+ 将所有转换的key按照key=value&的格式循环拼接，递归调用切分方法（为了取出对象中对象的key）例如：
```metadata json
biz_content=aviation_info=air_ticket_list=empty=&airlines_code=1&airlines_name=airlines_name&industry_type=1&travel_adult=1&travel_child=1&travel_infant=1&currency=USD&expire=2&language=en_US&out_trade_no=1573116190920&pages=pc&pay_amt=100&pay_type=00&charset=UTF-8&format=JSON&mer_id=120501000001&method=online.precreate.air&notify_url=http://localhost:8081/notify&return_url=http://localhost:8081/return&timestamp=1573116190920&version=1.0

```
+ 得到验签字符串signStr
+ 验证商户合法性
+ 通过商户号的到商户编号/签名算法类型/商户公钥/平台公钥/平台私钥
+ 通过验签字符串signStr/BaseRequestDTO签名串Sign/商户公钥/BaseRequestDTO加密算法，进行验签
+ 粗略描述：就是将验签字符串signStr（待验签名字符串），通过指定的商户公钥配合待验签名字符串加密，是否等于BaseRequestDTO签名串Sign
+ 详细描述：
    + 初始化KeyFactory指定加密规则rsa
    + 将公钥通过base64utils转换成byte[]
    + 使用KeyFactory通过以上公钥byte数组创建公钥对象PublicKey
    + 创建签名对象Signature
    + 给Signature添加已经初始化好的公钥对象PublicKey和将待签名字符串转成数组添加至Signature中
    + 调用Signature的verify方法验签，传入BaseRequestDTO签名串Sign
    + 相等返回true不想等返回false

##### 双向加签验签
+ a=》b a用私钥加签b用公钥验签
+ b=》a b用私钥加签a用公钥验签
