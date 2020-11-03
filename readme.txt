说明


1 一个简单的 windows下的代理程序. 

最初此项目的目的是过滤浏览器网址, 后来修改以查看 http/https流的内
容。

2 proxyo工程. 
不使用 openssl库, 可以实现 http/https的代理，不能查看https流的内
容，可以过滤网址(http/https)。

3 proxy工程
使用 openssl库实现的 http/https的代理，它使用 middle-proxy的方式
得到查看 https流的目的

openssl库采用 1.1.0以后(test.cpp)。在cert.self文件夹中用 openssl生
成了一个ca证书，用来给网站签名, 使用前需要将 ca证书导入到"受信任的
根证书颁发机构". ca证书用来给网站签名。

4 一些功能介绍
4.1 程序提供了两种模式，一种是代理模式，一种是端口重定向模式。
4.2 代理模式使用时要手工设置 ie代理. 代理模式下可以监控到浏览器的
数据。
4.3 重定向模式需要外部程序重定向端口到 proxy程序, 以达到 proxy可
以监控非浏览器程序的网络数据. 参考 CProxyServerPlug并修改以达到目
的. 
4.4 pcapf.h中支持将获取到的网络包写成 pcap格式. 
4.5 logf.h中可以加载外部组件(dll), 过滤网址. 这个是程序的原始需求. 
