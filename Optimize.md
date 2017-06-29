# 为什么需要优化网站：
大型网站的特点：      
访问的人多；                     
用户的同时访问人数，也就是同时在线人数太多，服务器受不了；            
网站信息量大；              
数据操作频繁；                          
像论坛的发帖、回帖，用户的注册，网上交易等等；这些都涉及到数据的操作；他们一般都涉及后台的数据库操作；            

## 总结：
高访问量；                
同时在线人数多；              
数据信息量庞大；                   
数据操作频繁；                         

## 网站性能测试指标：
网站的性能测试一般都包括：            
Web应用服务器方面；             
数据库服务器方面；            
系统服务器方面；                                          
这些方面都有相应的专业的性能指标，但是从客户的角度来看，通俗的指标，主要有如下几个：              
日访问量：                                      
也就是每天访问网站的人数；              
这个一般用于估算需要的带宽；              
同时在线的人数：                           
也就是同时访问网站的人数；                                                
这个指标一般用于考虑应该买什么配置的服务器的设备；                            
### 最大并发连接数：
也就是指网站服务器能够同时处理的链接请求数；                        
在购买网站服务器时就有这方面相应的性能指标；网站服务器运行时，再分配给相应的Web服务器；ISP服务器提供商一般就会告诉你，你的网站的最大并发链接数是多少；这样就可以避免你的网站耗尽网站服务器所有的资源；                           
一般的情况下，最大并发链接数最低为60到100；              
### 访问响应时间：
简单的说，就是用户输入某个网址之后，直到看到相应的网页显示所需要的时间；             
它实际包括：                 
网站服务器生成HTML的时间，网络传输时间，浏览器解析时间；           
因此，这个指标和带宽、网页的内容、网站服务器等等都有关系；                     

#### 同时在线人数和并发数有什么区别：
一般，网页当中都会存在有很多的图片，Web样式表，Web的JavaScript文件等；                             
当用户打开或者刷新网页的时候，浏览器就会向服务器发送多次请求，网页会请求，图片会请求，Web样 式表会请求，Web的JavaScript文件也会请求；那么，在这一时刻，服务器就会处理来自用户的好多的并发请求束；如果当前在线的一部分用户同时刷新网页，那么服务器收到的带请求连接数就会更多；虽然同时刷新网页的比率不是很大，但是一般来说，并发数都是大于当前在线的人数的                                   


### 网站性能具体体现：
首屏时间；             
网页访问可用性；            
建立连接时间；                      
DNS时间；                
重定向时间；                         
第一个数据包时间；                
总下载时间；                       
错误情况；            

#### 网站性能低下的原因：
客户投诉的问题：                    
网速慢；                     
个别页面打不开；                      

##### 是什么原因导致网站的性能如此低下呢？
需要加载的东西过多，比如：HTML代码，图片，CSS，JavaScript；如果，这些内容比较多，加载必然会受到影响；                           

优化网站的性能，主要靠的就是，经验，实践；                         
网上也有很大类似的经验总结，只要好好学习一些别人总结起来的有价值的经验，就可以大大的提高网站的性能了；                     

- 雅虎的黄金法则：                    
内容                   

服务器                        

Cookie                

CSS               

JavaScript                 

图片                         

移动应用                            



#### 使用YSlow插件分析网站性能：           
雅虎开发的YSlow工具，是运行在FireFox浏览器上面的，同时他还要依赖FireBug插件才能够运行；                     

##### 核心的优化方法：                                 
网页内容优化：                    
- 尽量减少HTTP请求次数；
	- 合并文件（Js或CSS文件）
		- CSS Sprites图片拼合（常用）
		- 图片地图（不常用）
		
- 减少DNS查找次数；    
减少主机名的数量可以减少DNS查找次数；           
指导原则：               
这些页面中的内容分割成至少两部分但不超过四部分；                 
结论：                     
减少DNS查找次数与保持并发下载兼顾；                                   
- 避免跳转；
	- 301代码；
	- 302代码；
结论：                   
开发时注意不要忽略URL本该有的斜杠` (/) `                                 

跳转可以采用配置`Alias`和`mod_rewrite`等方法来替代；                   
- 可缓存的AJAX；        
结论：                          
设置在客户端缓存；                      
- 减少DOM元素数量；                       
- 尽量避免使用iframe；           
优点：                                              
解决加载缓慢的第三方内容；                           
只需要修改一个iframe的内容，便可以改变所有应用该iframe的页面；               
缺点：                                             
即使内容为空，加载也需要时间；                
阻止页面加载；                           
没有语意；                                     
- 避免404错误；
首先，这种加载会破坏并行加载；                 
其次，浏览器会把试图在返回404响应内容当中找到可能有用的部分当作JavaScript代码来执行；                 
结论：               
网站发布前要进行周全的测试，使用一些ISP提供商的网站服务器工具来检查404错误；                         


##### 图片优化：
图片优化一般需要美工人员的配合；            
一下方面：                           
使用工具优化图片；                   
结论：                        
把所有的图片使用统一的jpg、gif或者png格式，行适当的转化，可以达到很好的优化效果；                                

使用合理的图片尺寸；                  
结论：                               
不在网页中缩放图片；                                             
网站图标`favicon.ico`要小而且可缓存；                              
结论：                    
`favicon.ico`文件不要缺少，而且文件尽量地小，可以缓存；                    
使用`CSS Sprites`优化页面小图片；                                                 
结论：
合理的应用`CSS Spirite`技术，不要在Spirite的图像中间留有较大空隙；                      

##### CSS和JavaScript优化：
不合理的使用CSS和JavaScript，同样会给网页加载带来很大的包袱；                          
优化方法：                         
把样式表置于顶部；                              
开发阶段将样式和代码分离，开发完毕后再将样式放在页面的<head>头部中；                              

##### 用<link>代替@import 
结论：                           
用<link>代替@import来实现外部样式表的导入；               

##### 避免使用滤镜；
结论：             
避免使用滤镜，使用PNG格式的图片来代替，主流浏览器一般都支持这种格式，必要时使用CSSHack来处理IE6浏览器下的效果；                     

##### 精简CSS和JavaScript；
结论：           
精简代码，采用缩写；                

##### 把JavaScript放在HTML的底部；
结论：                       
把脚本放在HTML页面的底部                  
(document.write()输出语句例外)


##### 优化Cookie      
缩小Cookie大小；             
结论：                      
去除不必要的Cookie，设置合理的过期时间；                             


##### 避免使用全局域名的Cookie；
结论：                  
应该对图片等页面元素使用没有Cookie的域名；             


#### 服务器端优化：
服务器端的优化包括硬件方面的优化和软件方面的优化；             
表现为如下方面：                 
使用内容分发网络；                       
结论：                      
##### 使用CDN（内容分发网络），但成本高；                 
为文件头指定Expires或`Cache-Control`            
结论：       
对于静态内容，设置文件头过期时间Expires的值为           
`"Never expire"` (永不过期)             

##### 使用Gzip压缩文件内容        
结论：           
开启应用服务器端的Gzip压缩设置；      

##### 使用GET来完成AJAX请求；
结论：      
获取数据时建议使用GET，相反，发送并在服务端保存数据时才使用POST；              



### 网站静态化    
从开发角度进一步讨论网站性能优化；              
随着Web技术的发展，越来越多的网站采用了动态技术；               
动态技术在网站维护和内容管理方面给我们提供了大大的便捷，但是这样也导致了一个问题：随着内容的增多，访问量的增大， 
动态页面的弊端也逐步的凸显出来；由于每次访问都需要通过服务器端处理页面内容，包括查询数据库等等，这样，就会给服务器端带来的压力是非常巨大的；                         
由于每一次请求都需要通过服务器端进行一个解释，因此页面响应时间久比较长；对于用户的体验就是不利的，同时由于动态页面需要对数据库进行一些操作，这样子还可能存在一些安全问题；那么有没有一种方法在不影响用户浏览的基础上减少服务器端                  
所做的工作：            
实际上，目前国内很多门户网站都采用了网站静态化这样一个技术来解决这个问题；              
实施静态化的原因：                            
静态化能提高网站访问速度；                           
减轻服务器压力；                  
加强安全性；                       
利于搜索引擎收录；                 


#### 如何静态化网站：
网站已经是动态化的了，如何升级为静态化的：     
其实，由于网站的信息量是非常巨大的，因此纯手工的来制作  
各个静态页面显然是不可行的；     
那么，目前，绝大多数的网站都是采用的模版技术来对网站进行
静态化操作；              

#### 网站静态化的好处：
效率方面       
 纯静态化HTML页面            
 减轻服务器的压力               
 利于搜索引擎收录             
 提高服务器的性能                   
安全方面           
 防SQL注入                        
 网站出错时，不影响网站正常访问                


##### 效率方面
 纯静态化HTML页面           
	- 效率最高
	- 消耗最小
	- 速度最快

所谓纯静态的HTML页面，是指没有任何需要服务器端解释的页面，包括动态脚本，数据库交互等等；       
一般，他的后缀是 `.htm `或者是 `.html` ；                             
由于不会经服务器做任何的解释，所以从效率上讲，静态页面的效率是最高的；而他消耗的资源却是最小的；服务器端收到用户的请求以后，将直接把静态页面的内容发送给客户端浏览器，所以，在速度方面，静态页面的打开速度，也明显优于动态页面；                   


减轻服务器的压力                               
首先看一下，用户从请求动态页面，到接收到服务器返回的信息的整个过程：                  
当服务器接收到用户的请求以后，首先要做的事情就是，解释页面中的动态脚本；这中间，如果涉及到数据库的相关操作的话，
脚本就会通过查询语句链接到数据库，取得相应的内容，然后显示到对应的区域，最后才将最终的HTML代码返回给客户端浏览器；             
服务器经历这些过程，无疑做了很多的工作；假如短时间内，有很多的客户请求的话，那么服务器就会变得繁忙无比；                
而静态页面就相当简单了；当服务器收到用户请求以后，几乎什么都不需要做，直接将对应的静态页面返回给客户端浏览器，就完成了本次操作；                         


利于搜索引擎收录                            
动态网页虽然能够使用同一个页面来实现多个页面的工作，但是他对搜索引擎来讲，并不友好；由于动态页面的生成，是采用数据库的内容，所以网页内容主题的永恒性并不能保证，这样就造成了搜索引擎的阅读困难，也就是，搜索引擎抓不住一个永恒的主题；因此，不能输入到搜索引擎当中的缓存当中；另外，动态链接存在一个信任问题；用户，以及搜索引擎都无法确定这个页面会一直存在；                       
搜索引擎对于静态链接就更加友好；                      
所以，把动态网址进行URL重写，使其静态化，是一个非常重要的优化技巧；            


提高服务器的性能                              
动态网页操作数据库，对用户整个请求来讲，一般来说都是最耗时的一个阶段；为了获取数据库中长期不变的几条数据，而对数据库进行频繁的读写，显然会让服务器的性能变得非常的低下；                   
如果同时处理的请求过多，可能还会出现排队的现象，这样用户等待的时间自然就会变得更长；                                  
前面讲过，静态页面的另一个好处就是，不用调用数据库；服务器所要做的工作，仅仅是把HMTL代码原封不动的返回给客户端浏览器；因此，服务器的CPU消耗就会大大的减少，这样也就提高了服务器的性能；                       




#### 安全方面
 防SQL注入                 
什么是SQL注入：                 
所谓SQL注入，就是通过把SQL命令插入到Web表单提交；或者是输入域名，或者是页面请求的查询字符串；那么最终达到欺骗服务器，执行恶意的SQL命令；这一般都是网站对用户提交的数据过滤不严格所导致的；                                              
由于静态页面，根本就不存在数据库相关的任何操作；因此，也就从根本上杜绝了SQL注入的可能性；                                 



网站出错时，不影响网站正常访问               
动态网站，还存在着一个问题：                         
如果页面发生错误，或者是数据库出现了问题；那么，从数据库读取数据的页面，就必然无法正常的访问了；那么呈现给用户的，可能就是一个  错误页面，用户就不能浏览到对应的信息了；                
而静态化，就可以完全避免这个问题；                          
由于静态化操作，只是在生成静态页面的时候，链接数据库，而生成之后便不会对数据库数据库进行任何的操作了；因此，即便是数据库服务器出现问题，甚至于崩溃，用户仍然可以正常的浏览到对应的信息；                    



##### 网站静态化实现方式
对我们做的网站，必要的部分实行静态化操作，提高网站的整体性能；                              
同一网站的下的不同页面，风格一般都要保持一致，他们所不同的只是里面的内容罢了，因此我们需要做一些工作，让静态化的时候能够重用页面的整体框架，风格，等等；这里的框架，风格，就是要学习的模板技术；                   
对于 `ASP.Net PHP  JSP`等各类动态网站，静态化的技术一般都是采用模板技术来完成的；      

模板技术

其实，对于Java动态页面，我们有很简单的方式就可以实现页面的静态化操作；              
一般，我们采用 Velocity 或者是 FreeMarker 等模板框架来实现；                     


##### Velocity：
Velocity是一个基于Java的模板引擎，他运行任何人仅仅简单的使用模板语言来引用由Java代码定义的对象；        
当Velocity应用于Web开发时，界面设计人员可以和Java程序开发人员同步开发一个遵循 WVC架构的Web站点；也就是说，页面设计人员可以只关注页面的显示效果，而Java程序开发人员只关注业务逻辑编码；                    
Velocity将Java代码从Web页面中分离出来；这样，为Web站点的长期维护，提供了便利；              
由于熟悉Velocity模板引擎需要一个过程，在这里只是做一个了解；                   



##### 为什么需要优化数据库查询
现在，通过优化网站程序，实现了网站前台页面的静态化；大部分的网页已经生成了静态页面；这时，浏览者在网站上浏览一些信息时，可以直接访问已经生成的静态页面了，而无需访问数据库；这样，就极大的减少了数据库的负担；那么，是不是将网站页面生成静态页面，就能够完全解决网站性能问题呢；                
网站上的大部分页面生成了静态页面；但是，某些页面可能并不适合进行静态化；比如，一些更新比较频繁的页面，以及一些查询页面等等；他们还是需要查询数据库的，所以页面静态化只是解决了大部分页面性能差的问题；如果要提升网站的整体性能，还需要做一步，就是：优化数据库查询部分；                               


##### 常用的SQL查询优化法则
其实，数据库的查询优化方法也是有章可循的；主要体现在以下几个方面：       

在查询频繁的列上添加合适的索引    

尽量少用 IN 或 `NOT IN`

尽量少用 通配符` * `         

尽量少用 LINK            


#### 在查询频繁的列上添加合适的索引：
索引，作为数据库中的重要数据结构，他的根本目的就是为了提高查询的效率；而优化查询的重要方法就是建立索引；建立适合关系型数据库的索引，这样就可以避免表扫描，并减少了因为查询而造成的输入输出开销，有效的提高数据库的查询速度，优化了数据库的性能；            
然而，在创建索引时，也增加了系统的时间和空间上的开销，所以创建索引时应该与实际的查询相结合；这样才能够实现真正的优化查询；            
首先，判断并建立必要的索引；                 
对于所要创建的索引，进行正确的判断，使所创建的索引对数据库的工作效率提高有所帮助；                
其次，对索引使用一些规则；                     
索引的使用，在一些大型数据库当中经常使用到；那么，这样可以有效的提高数据库的性能，使数据库的访问速度得到提高；               
第三，合理的索引对SQL语句要有意义；               
那么，索引建立之后，还要确保其得到了真正的使用，发挥其         
应有的作用；       


##### 尽量少用 IN 或者 `ONT IN`
在使用索引时，可以有效的提高查询速度，但是如果SQL语句写的不恰当，那么所建立的索引就不能发挥其作用；            
所以，我们应该做到，不但会写SQL，还要写出性能优良的SQL语句；             
在 WHERE子句当中，应该尽量避免使用 IN 或者` NOT IN` ，                   
可以使用 EXIST 或者 `NOT EXIST` 来代替 IN 和` NOT IN` ；                  


##### 尽量少用 通配符 `*`       
在进行查询时，返回的值，应该是查询所需要的；在查询当中，应该尽量减少对数据库当中的表的访问行数，使查询的结果范围最小；         
尽量避免使用 通配符 `*` ；      
这就意味着，在查询时，不能过多的使用 通配符 ；         
例如： `SELECT *  FROM table1；`这条语句；          
而应该做到最小化查询范围；要查询几行几列，就选择几行几列，例如： `select col1 from table1`                   
那么多数情况下，用户并不需要查询到所有的数据，而只是一部分，或者是靠前的数据；那么这个时候，我们也可以通过SQL语句来进行限制查询，例如：查询前50条信息的语句：                                    
```SQL
select top 50 col1 from table1
```

##### 尽量少用 LINK            
由于使用LINK，在查询完成时变量的值不确定，所以无法使用索引；这样子，建立的索引也就失去了意义；这就严重的制约着查询的速度；


### 性能监测
为什么需要监测网站的性能：                   
性能环境发生改变；              
通过前面的优化，我们已经有能力将性能方面做的很好了；                 
但是，网站的性能，是随着浏览量以及硬件设施的不同，而发生改变的；因此，网站正式运营之前，以及运营期间，我们有必要对网站的整体性能进行监测，从而避免正式运营以后，所面临的各种性能问题；                  
在性能监测方面，我们主要是靠软件来完成的；                  
开发人员需要根据性能测试分析报告，对网站进行优化或者是代码维护；                               


#### 使用软件监控网站的性能
网站性能监测，主要分为两个阶段来完成；           
首先是：                
网站开发期间；                    
 
然后就是：            
网站运营期间；                              

这两个阶段的性能监测都是不可缺少的；        


#### 网站开发期间
在网站开发期间，使用LoadRunner等专业的负载测试工具；          
LoadRunner是一组预测系统行为和性能的负载测试工具；             
通过模拟上千万用户实施并发负载，及实时性能监测的方式，来确认和查找问题；                
LoadRunner能够对整个企业框架进行一个测试；通过使用LoadRunner，企业能够最大限度的来缩短测试时间，优化性能和加速应用系统的发布周期，                           
LoadRunner的强大之处，可以从以下几个方面来进行描述：            
轻松创建虚拟用户；           
创建真实的负载；            
定位性能问题；                              
分析结果以精确定位问题所在；                         
重复测试保证系统发布的高性能；          


##### 轻松创建虚拟用户
使用Loadrunner的`Virtual User Generator`，能够很简便的创立起系统负载；该引擎能够生成虚拟用户，以虚拟用户的方式，模拟真实用户的业务操作行为；           
##### 创建真实的负载
`Virtual Users` 建立起来以后，需要设定负载方案，业务流程组合和虚拟用户数量，用 LoadRunner的Controller就能够很快的组织起多用户的测试方案；            
##### 定位性能问题
LoadRunner内含的实时监测器，在负载测试过程的任何时候，都可以观测到应用系统的运行性能；        
分析结果以精确定位问题所在                
一旦测试完毕以后，LoadRunner收集汇总所有的测试数据，并为你提供高级的分析报告工具，以便迅速查找到性能问题，并追溯缘由；
重复测试保证系统发布的高性能                
利用LoadRunner，可以很方便的了解系统的性能；它的Controller允许你重复执行与出错修改前相同的测试方案；            
它的基于HTML的报告，为你提供一个比较性能结果所需的基准，以此衡量在一段时间内有多大程度的改进，并确保应用成功；               
 
由于整个过程比较复杂，因此LoadRunner测试工作，一般都是由专业的测试人员来完成；               



#### 网站运营期间的监测
上面所说的监测，都是在网站开发期间操作的；             
一般都是为了避免网站正式运营阶段可能遇到的问题；                     
那么，在网站运营阶段，我们还需要继续对网站性能进行监测；                
随着网站内容量的增大，以及访问量的增加，运营期间面临的问题，可能会更多；因此，这个阶段，我们也需要对网站的性能进行着监测；       


##### 常用的在线监测工具比较多，有：
```
国内的监控宝；
美国的 SERVICE UPTIME
UptimeRobot
Site24X7
```

等等，这些工具的功能都非常的强大，统计项目都很多；




### 总结：
1.为什么需要优化网站：                                    
1.1 大型网站的特点：           
```
高访问量                   
 同时在线人数多          
 数据量庞大           
 数据操作频繁                          
```

1.2 网站性能测试指标         
```
日访问量                         
 常用页面最大并发数           
 同时在线人数              
 访问响应时间                              
``` 

1.3 网站性能具体体现                
```
 首屏时间               
 网页访问可用性             
 建立连接时间                     
 DNS时间                     
 重定向时间                                    
 第一个数据包时间                          
 总下载时间                 
 错误情况                         
```


2.网站性能优化                                                                    
2.1 使用YSlow插件分析网站性能            
 
2.2 网页内容的优化                          
```
 尽量减少HTTP请求次数           
 减少DNS查找次数              
 避免跳转                     
 可缓存的Ajax               
 减少DOM元素的数量                               
 尽量避免使用iframe            
 避免404错误            
```

2.3 优化图片                  
```
 使用工具优化图片          
 使用合理的图片尺寸                              
 favicon.ico要小而且可缓存                
 使用CSS Sprices优化页面小图片                       
```

2.4 优化CSS和JavaScript     
```
 把样式表置于顶部
 用<link>代替@import
 避免使用滤镜
 精简CSS和JavaScript
 把JavaScript放在HTML的底部
```

2.5优化Cookie
```
 缩小Cookie大小
 避免使用全局域名的Cookie
```
2.6 服务器端优化
```
  使用内容分发网络
  为文件头指定Expires或Cache-Control
  使用Gzip压缩文件内容
  使用GET来完成AJAX请求
```

3.网站静态化                       
3.1 网站静态化的好处
```
 效率方面
 安全方面
```

3.2 网站静态化实现方式          
```
 对于ASP.NET PHP JSP等各类动态网站，静态化的技术一般都是采用模板技术
 对于Java动态页面，一般采用Velocity、FreeMarker等模板框架来实现
 模板技术的原理
```

4.数据库查询优化                     
  常用的SQL查询优化法则 

5.性能监测                   
 5.1使用软件监控网站定位性能