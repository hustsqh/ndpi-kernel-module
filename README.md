# ndpi-kernel-module

根据项目https://github.com/betolj/ndpi-netfilter 修改，把ndpi模块单独抽出来，不和xtable绑定，放在连接跟踪后面。


* ndpi版本 2.8-stable
* linux ubuntu 18.04， kernel 4.15.18

后续的工作：
* 使用conntrack替换掉ndpi中的连接信息
* 去掉锁
* 优化性能
* 将规则匹配作成配置，以便更新
