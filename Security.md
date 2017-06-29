# 安全的基础知识：

- 网站安全的重要性；    

- 基本的安全属性；   

- 网站入侵的攻击方法和原理；   

- Web安全的防御思路；



## 网站安全的重要性；
网站安全的应用场合：    
 电子商务；    
 电子政务；     
 票务系统；    
 公司内部系统；      


## 常见的网站安全问题：
拒绝服务(Dos-Denial of service)    
现象：     
大规模无效访问，造成网络堵塞，用户无法连接；            

### 非法登录
获得网站用户的密码，在网站上为所欲为；     
原因：        
程序中被植入了木马；常见的木马程序监听键盘输入；              

### 数据库级别
任意改变数据库数据；     
出售数据库数据；        
数据库中有大量用户的注册信息；            
数据库是网站的核心；失去了数据库就失去了一切；            
通过SQL注入，获取数据库信息，甚者，篡改数据库信息；出售数据库信息；                 

### 获得网站管理员权限    
权限突破               
原因：           
网站管理混乱              
无基本保护               



## 基本的安全属性：
- 机密性

- 完整性

- 可用性

- 可靠性

- 不可否认性



## 网站入侵的攻击方法和原理

- 暴力破解

- SQL注入

- 上传漏洞

- XSS跨站攻击

- Cookie诈骗

- Dos攻击



### 暴力破解

攻击原理     
攻击内容：      
各种登录密码                   

利用工具反复性的试探攻击                   

缩小海量级试探次数的方法                    
字典档                   
规则破解                           

#### 常见的攻击方法：
- 远程通讯法           
`Who?web/pop/telent?`        
- 确定攻击目标
- 建立多进程的socket通信
- 通过字典档或规则生成密码
- 发送密码试探

#### 本地文件破解
- 截取加密后的密码（密文）             
- 通过字典档或规则生成密码明文            
- 将密码明文按加密算法加密              
- 将生成的密文和截取密文比较                     



### SQL注入
攻击原理             
在Web表单或查询字符串中输入特殊的SQL命令              
实现欺骗服务器或绕过登录验证              


###  上传漏洞
攻击原理     
利用上传漏洞直接得到webshell              
网站服务器的安全漏洞：            
字符过滤不严格                
文件类型未检测                
上传未加权取                  


### XSS跨站攻击    
`XSS-Cross Site Scripting`           
穿越网站脚本   通过脚本可以跨越网站内部结构                      
攻击原理                             
恶意用户在网页中插入HTML或JS脚本             
引诱用户点击或输入用户隐私数据                       
黑客获取用户账号、Cookie等隐私数据                      
#### 常见的攻击方式：
- js方式                 
- iframe方式             
- Ajax方式            

### 钓鱼邮件：
邮件内容时知名网站的邀请函等           
引诱图片链接                      
论坛或网站上的诱人图片,他们都暗藏恶意链接，欺骗用户点击                        


### Cookie诈骗
原理：                      
Cookie是存放在客户端的用户数据                       
黑客可以通过修改本地Cookie来冒充管理员或用户                            


### Dos攻击
`Dos-Denial of service(拒绝服务攻击)`            
目前更流行DDos-分布式拒绝服务攻击                        
- 攻击原理和过程：                                       
Web安全的防御思路          
- 防御思路：                
增加防御物（防火墙、VPN）                   

控制传输 - 加密                        

确认身份 - 认证（who?）                          

控制访问资源 - 授权（能访问什么）                      

跟踪操作 - 审计和日志（你做过什么）                          



## Web开发中的安全编码
严格验证用户输入的数据，如： SQL注入，XSS安全漏洞                
- 输入验证                                  

- 防范跨站脚本XSS工具                

- 防止SQL注入

- 图片验证码


- 输入验证                                      
经典的安全法则：`永远不要相信用户提交的数据`                         
用户提交的数据永远都是需要验证的；                   
验证内容：                       
用户名、密码等格式                     
验证长度防止数据库溢出错误                              
邮件、手机、邮编等格式                               


- 验证输入的方法               
客户端：                                   
写JS脚本验证，过滤用户输入                              
服务器端：                      
检测用户输入的合法性                     
强制转换用户输入                        
数据入库约束验证                       


#### 防止SQL注入
SQL注入的解决思路                      
- 客户端：                                
过滤或转义危险字符                            
使用正则表达式限制输入                                     

- 服务器端：                   
控制数据库的访问权限           
分布验证用户名和密码                  
对账号做加密处理                       



### 图形验证码
目的：避免暴力攻击               
验证码的原理：                                                        
1.服务器端随机生成验证码字符串，并写入图片                                 
2.发送图片，同时存入Session                    
3.客户端提交输入的验证码及表单数据                                      
4.服务器端读取Session，和用户输入的验证码比较                        
5.根据比较结果确定是否执行DB操作                                         



### 防范跨站脚本XSS攻击
解决思路：                           
实现严格的输入验证                      
过滤`iframe、script、expression`                
实现Session标记等                     
进行HTML的格式化                          


#### 数据加密
- Java提供的安全模型和API                

- 加密基础知识                     

- 使用Java实现加密



#####  Java提供的安全框架和API
- Java语言本身的安全性

- Java加密体系

- Java的认证和授权

- 安全通信

- PKI体系

`（在Java DOC帮助文档中有详细的API说明）`     


#### Java提供的安全框架和API
- Java语言本身的安全性                            
- 自动内存管理                     
- 自动数组溢出检查等                      
- 字节代码的验证机制                 
- 独特的安全类加载                   
........              
- `Sandbox Model`沙漏模型      

### Java加密体系
JCA和JCE是两个重要框架                      
```
JCA-Java Cryptography Architecture
JCE-Java Cryptography Extension
```
#### JCA
- 数字签名             
- 信息摘要             
- JCE                 
- MD5(消息摘要算法)               
- SHA(安全散列算法)            
- DES(数据加密算法)              

算法和实现的独立性


#### Java的认证和授权
基于配置文件的认证和授权             
 只需配置配置文件，方便修改                 
 应用场合：一般适用于B/S开发              
 安全控制粒度：一般只能到某个页面                        
基于源码的认证和授权                                         
 安全控制粒度：可以控制到某个类甚至方法                   
 应用场合：C/S或B/S开发均可                     
```
 JAAS-Java Authentication and Authorization Service
```
### 安全通信
Java提供了对于标准通信协议的实现API             
```
SSL - Secure Socket Layer(安全套接层协议)
TLS - Transport Layer Security(安全传输层协议)
Kerberos (一种网络认证协议)
```

## PKI体系
`PKI - Public Key Infrastructure`
Java的PKI规范提供了管理key和证书的API                
### 实现协议                          
- X.509(最常用)           
- CRL(证书撤销列表)           
- PKCS等               
### PKI的核心是数字证书
- 提供Certifficate数字证书对象等
### 管理证书的工具
- keytool
- jarSigner


### 加密基础知识
- 对称加密（私钥体系)    
特点：                                                
单玥，用同一把钥匙加密和解密                               
加密/解密速度快，安全性取决于私钥的保管            
#### 典型算法：
- DES(数据加密算法，58位，安全性不够高)
- AES(高级加密标准，128位，常用)

- 非对称加密(公钥体系)
特点：                   
加密用公钥，解密用私钥              
安全性较高，加密/解密慢，适用于分布式网络               
典型应用：数字证书           
##### 典型算法：
- RSA
- DSA

### 单向散列函数
`h = H(m)` 返回长度为m的散列值h            
特点：                            
加密快，不可逆，破解困难         
##### 典型算法： 
- MD5 (128位，安全性不够高)
- SHA 或 SHA1 (160位)


### 使用Java实现加密
使用MessageDigest类实现md5、SHA加密         
```java
//导入安全包security 
import java.security.*;
public class HashEncode {
....
//创建MessageDigest对象
MessageDigest md5 = MessageDigest.getInstance("MD5");
//使用update()方法更新要加密的内容
md5.update(crybyte);
//使用digest()方法加密
byte[] hashCode = md5.digest();
......
}

使用KeyGenerator和Cipher类实现AES堆成加密
//导入密码包.crypto
import javax.crypto.*;

public class SymmetricEncode {
....
//创建KeyGenerator对象
KeyGenerator keygen = KeyGenerator.getInstance("AES");
keygen.init(128);
//产生一个对称密钥
SecretKey original_key = keygen.generateKey();
....
//创建Ciper对象
Cipher cipher = Cipher.getInstance("AES");
cipeher.init(Cipher.ENCRYPT_MODE,key);
//doFinal()加密
byte[] byte_AES = cipher.doFinal(byte_encode);
.....
KeyGenerator keygen = KeyGenerator.getInstance("AES");
keygen.init(128,original_key);
//doFinal()加密
byte[] byte_decode_AES = cipher.doFinal(byte_content);
.....
}
```

### 基于页面级的认证和授权
Servlet规范规定的身份认证方式                 
Servlet规范 - `Tomcat/Weblogic`                   
基于角色的用户管理            
- 用户 - user                    
- 角色 - role                  

角色 - 类似Windows中的用户组                       
采用角色管理的好处：                          
不同的角色可以进行不同的操作                

##### Servlet规范中基于角色控制的实现思路：
- 域(realm) 用户的集合         
- 用户 (user)            
- 密码 (password)          
- 所属角色 (role)            

`Tomcat -> Rcalm`  用户、角色：`tomcat-users.xml`              
访问权限 `web.xml`

#### Servlet规范规定的4种认证方式：      
- Basic验证                  
 明文传送口令、安全性低        
 
- Digest验证         
 消息摘要方式传递，安全性较高            
 
- Form验证         
 安全性低，但可以自定义             
Client - cert验证                
 数字证书方式，一般和SSL配合                   

##### Digest验证
实现Digest验证的步骤：         

- 配置`tomcat-user.xml`(也可以配置在各应用下)     
```
<role rolename="角色名"/>
<user username="用户名" pass="加密后的密码" roles="所属角色名"/>
```

密码用digest命令加密                 

- 配置`server.xml`，设为Digest验证方式      
```
<realm className="......" digest="md5"/>
```
- 配置具体应用下的`web.xml`
```xml
<security-constraint>
  <web-resource-collection>
    .......
   <url-pattern>受限页面url</url-pattern>
   <http-method>GET</http-method>
   .......
   </web-resource-collection>
   <auth-constraint>
     <role-name>能访问的角色名</role-name>
 <login-config>
   <auth-method>digest</auth-method>
   <realm-name>域名</realm-name>
 </login-config>
```

- Form验证          
实现Form验证的步骤：         
更改`web.xml`文件              
```xml
<login-config>
   <auth-method>FORM</auth-method>
    .......
   <form-login-config>
      <form-login-page>登录页url</form-login-page>
      <form-error-page>错误页url</form-error-page>
   </form-login-config>
</login-config>
```

设置登录表单页           
```html
<form action="j_security_check" method="post">
  userName:<input type="text" name="j_username"><br>
  password:<input type="text" name="j_password"><br>
   <input type="submit" value="authenticate">
</form>
```

### 如何将用户、角色信息放入数据库？
- 创建用户表和角色表         
```
用户表(userName password)
角色表(userName roleName)
```
- 更改`Context.xml`文件，设置数据库驱动等信息      
```xml
<Context>
 <Realm className="org.apache.catalina.realm.JDBCRealm"
 driverName="驱动程序名称" connectionURL="URL"
 userTable="用户表名"  userNameCol="用户字段名"
 userCredCol="密码字段名"  userRoleTable="角色表名"
 roleNameCol="角色字段名"/>
</Context>
```
**注意**：             
将驱动程序的jar文件放入到tomcat的commonlib下        

#### 数字证书验证
为什么需要数字证书？                 

- 数字签名的原理：                  
数字签名：公钥+私钥的一种应用                     

- 常用的数字签名算法：            
RSA或DSA数字签名算法                      

- 数字证书：数字签名的一种应用               

##### 第三方认证
```
CA-Certificate Authority 证书发布机构
```
编译： javac 文件名 .java                    
```
SSL-Secure Socket Layer 安全套接层协议
```

### JAVA中数字证书的实现思路
- 使用keytool等工具生成服务器端密钥仓库              
- 在Tomcat中配置启用SSL              
- 导出服务器端证书                      
- 生成客户端密钥仓库                 
- 在客户端导入服务器端证书                     



## 什么是JAAS
```
JAAS - Java Authentication and Authorization Service
Authentication : 认证
Authorization : 授权
```
### JAAS的特点：
- JAAS是JCE安全框架的重要补充                         
- 提供基于用户认证和授权的动态安全解决方案                             
- 可拔插(Pluggable)方式，JAVA程序和底层认证分离                   

### JAAS的安全认证特点和实现机制


### JAAS认证
认证方面的常用类和接口               
```
LoginModule ：登录模块
LoginContext ： 登录上下文
CallbackHandler ： 回调处理器
Subject ： 验证实体/主体
Principal ： 身份/标识
```

#### 认证原理
```java
//配置文件 ： login.config    设置JAAS配置文件
jaas_sample {
//初始化loginContextd对象，根据配置文件加载一个或多个LoginModule
.....UserPasswordLoginModule required;
.....OptionLoginModule optional;
};

//主程序代码：
LoginContext loginContext = null;
.....
loginContext = new LoginContext("jaas_sample",
new UserCallbackHandler());
....
try {
//通过调用LoginContext的login方法，最终将调用每个LoginModule的login方法来实现验证
loginContext.login();
} catch (LoginException e) {
System.out.println("登录失败");
}
....
```

#### JAAS认证的JAVA实现              
- 编写主程序验证代码（客户端代码）                            
- 自定义登录模块（实现LoginModule接口）                          
- 创建用户信息管理类（实现CallbackHandler接口）
- 实现身份标识类（实现Principal接口）
- 配置认证策略文件`（*.config)`

##### 自定义登录模块（实现LoginModule接口）
```
abort()
commit()
initialize()
login()
logout()
```

- 创建用户信息管理类（实现CallbackHandler接口）           
`handle(Callback[] callbacks)`                    
常见的callback类别                            
```
  NameCallback
  PasswordCallback
```

- 实现身份标识类（实现Principal接口）
```
equal
getName()
hashCode()
toString()
```

- 配置认证策略文件`（*.config)
```
required （必须）
optional （可选）
requisite （必须）
sufficient （充分）
```
- 执行时指定配置文件
```
java -Djava.security.auth.login.config=login.conf
```


#### JAAS授权的实现
JAAS授权的实现机制                          
用户通过认证 （已确认你是谁）                       
配置基于Principal的授权策略文件           
```java
//配置授权策略文件： *.policy
grant Principal ......UserPrincipal "bdqn" {
  permission ......SimplePermission "operate";
  permission ......SimplePermission "access";
};

//用Subject的doAS/doAsPrivileged()执行敏感资源的访问

//授权的主程序文件
//....通过身份认证（验证）后....
Subject mySubject = lc.getSubject();
PrivilegedAction action = new SampleAction();
Subject.doAsPrivileged(mySubject,action,null);
......
```

#### JAAS授权的JAVA实现
- 实现授权的主程序代码                        
- 实现敏感资源访问类（实现PrivilegedAction接口）              
- 配置授权策略文件 `jaas.policy`


1.以指定的身份执行特权动作来访问敏感资源                                
```
 doAS (subject,action)
 doAsPrivileged (subject, action,指定的访问控制上下文对象)
```

```java
//......身份验证
//调用login()方法后，被验证实体subject将填充表示能访问敏感资源的一个活多个Principal
loginContext.login();
//......通过身份验证后
//获得通过验证后的subject
Subject mySubject=loginContext.getSubject();
//创建访问敏感资源的特权动作action在run()方法中具体实现
PrivilegedAction action=new CheckAccountAction();
//以subject 的身份来执行特权动作（访问敏感资源）
Subject.doAsPrivileged(mySubject,action,null);
```

2.实现敏感资源访问类（实现PrivilegedAction接口）                            
实现run()方法                
```java
public class CheckAccountAction implements PrivilegedAction {
 public Object run() {
     //....访问敏感数据的操作
  }
}
```

3. 配置授权策略文件 `jaas.policy`              
语法        
```
grant <signer(s) 签名者>,<codeBase 代码源url>
 <Principal 标识类> {
   permission 权限类名 "target_name","action";
   ...
   permission 权限类名 "target_name","action";
};
```


## 总结

安全的基础知识                
	- 基本的安全属性                               
	- 网站入侵的攻击方法和原理                       
web安全的防御思路                       
 
Web开发中的安全编码                 
 输入验证                      
 图片验证码                             
 防范跨站脚本XSS攻击                     
 防止SQL注入                             
	- 过滤或转义危险字符            
   	- 分布验证，并做加密处理

数据加密
	- Java提供的安全模型和API
加密基础知识
	- 使用Java实现加密

基于页面级的认证和授权
	- Servlet规范规定的身份认证方式               
	- DIGEST验证             
	- FORM验证            
 数字证书         
- 使用keytool等工具生成服务器端密钥仓库         
- 在Tomcat中配置启用SSL          
- 导出服务器端证书           
- 生成客户单密钥仓库                
- 在客户端导入服务器端证书         


基于代码级的认证和授权           
什么是JAAS             
实现JAAS认证          
实现JAAS授权                             

#### 认证
- LoginMoudle
- CallbackHandler
- loginContext
- xxx.config
#### 授权
- Principal
- Subject
- Permission
- Permission
