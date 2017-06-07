# 图片挑战介绍

一般与图片相关的主要有隐写，图片格式了解。

# 基本工具

## strings

- 查看是否有特殊字符串，比如flag

## dd

- 读写文件中的  固定部分

## binwalk

- 介绍
  - http://www.freebuf.com/sectool/15266.html
- 查看文件是否有隐写
  - -e，提取信息

## foremost

- 分离文件

## 010Editor

- 解析文件的格式
- 有时候文件本身的格式可能会有问题，需要我们自己去进行简单的修补。

## stegsolve

- 各种文件隐写处理
- [stegsolve](http://www.caesum.com/handbook/Stegsolve.jar)下载。

# 基本策略

下面的是一般对于图片类型挑战的基本策略，呈递进方式。

## 图片属性获取

- file，文件基本属性
- strings，简单字符串
  - **jarvisoj-basic-veryeasy**

## 图片基本信息

### 方法

- 谷歌搜索
- 图片本身自带信息

### 信息点

- 时间
- 地点
  - 经纬度
  - 地区
- 人物、风景
- 文件属性

## 图片是否正常

- 010editor
- 有时候给的文件可能本身有问题，需要我们根据文件本身的格式进行修补。

## 图片是否存在padding

- 文件尾信息

## 图片隐藏信息判断

### binwalk

### stegdetect

### outguess

- 秘钥
  - 文件名
  - 题目重点词
  - 风景
  - 人物
- 适合于多种判断

## 隐藏信息提取

对于不同的载体，可能会有不同的策略，当然还会有一些比较通用的策略。具体的参见可以参见下面更加具体的介绍。

# 参考资料

[隐写术总结](http://www.tuicool.com/articles/mu6Jv2)
