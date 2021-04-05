# 主机特征绑定木马

## 简介

我们在搞下一台机器的时候需要留下一个后门作为下次造访的通道，那么这个后门能存活多久同时不被发现就是我们首要解决的问题，借鉴以往同行的经验，通常我们可以使用一些反沙箱与反调试的功能来保障木马的存货，但这也只是缓兵之计，只要我们定制的木马体作为样本被上传到云端，那么这个马距离全球联保的时间也不远了，那么我们有没有一种方法可以保障我们的木马无法被分析呢。

由于是出于驻留目的编写的木马，所以不用考虑泛用性。

本文提出两种思路，第一种思路是使木马无法脱离当前环境执行，第二种对抗杀软使其无法上传样本。

## 思路

### 1.主机绑定

1. 使用主机特征加密实际木马体。
2. 读取Machine id\(也可使用其他主机特征\)加密木马体\(如shellcode\)
3. 使用读取到的machineid加密shellcode
4. 编写读取当前主机machineid并尝试解密执行的木马

### 2.执行分离

1. 将木马体写在无法上传的位置
2. 编写定制执行器

## 伪代码

windows会在安装后生成一个product ID\(可以使用主板序号、cpu编号、用户名等主机特征\)该值理论上唯一，我们可以读取这个值作为密钥加密我们的木马体，然后编写读取当前环境值的加载器。  

![](../.gitbook/assets/image%20%28286%29.png)

这个就写伪代码了。

加密部分

```text
shellcode="XXXX"
key = read('xxx')
def encode(key,shellcode){
    自有算法处理shellcode
    return encode_shellcode
    }
print encode(key,shellcode)
```

解密部分

```text
encode_shellcode="xxxx"
key = read('xxx')
def decode(key,encode_shellcode){
    自有算法解密shellcode
    return shellcode
}
shellcode=decode(key,shellcode)
shellcode()
```

