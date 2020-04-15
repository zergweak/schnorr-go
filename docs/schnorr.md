# schnorr签名算法

### 初始化
p: 有限域的阶 <br>
G: 椭圆曲线基点 <br>
N: 椭圆曲线的阶 <br>

### 密钥生成
生成256位随机数r <br>
d = r mod N, d就是用户私钥 <br>
P = dG, P就是用户公钥  <br>

### 签名验证
#### 签名
输入: 数据msg, 私钥d <br>
计算 P = d*G <br>
计算 k0 = getK0(msg, d) <br>
计算 R = k0*G, 其中Rx, Ry为R的坐标 <br>
计算 k = getK(Ry, k0) <br>
计算 e = getE(Px, Py, Rx, msg) <br>
计算 s = (k + e*d) mod N <br>
输出签名: (Rx,s)

#### 验签
输入: 数据msg, 公钥P, 签名(Rx,s) <br>
计算 e = getE(Px, Py, Rx, msg) <br>
计算 X = s*G <br>
计算 Y = e*P <br>
计算 R' = X - Y = s*G - e*P, 其中Rx', Ry'为R'的坐标 <br>
如果 Rx' 等于 Rx, 且Ry'是p的二次剩余, 则验证成功 <br>

#### 公式
##### getK0(msg, d)
k0可以是随机数，也可以由 msg和d分散计算. <br>
本方案中如下： <br>
计算 P = d*G, 其中Px, Py为P的坐标 <br>
计算 hmac = hmac512(Px, Py||msg)  <br>
取 hmac的前32字节, 得到h  <br>
计算 k0 = (d + h) mod N <br>

##### getK(Ry, k0)
如果Ry是p的二次剩余, k = k0 <br>
否则 k = N - k0  <br>

##### getE(Px, Py, Rx, msg)
e = sha256(Rx||Px||Py||msg)  <br>

##### 证明
R' = X - Y = s*G - e*P = (k + e*d)*G - e*d*G = k*G  <br>
R = k0*G        <br>
由于 k = k0 或者 k = N - k0 <br>
所以 R' = R 或者 R' = -R <br>
所以 Rx' = Rx <br>
由于 Ry是p的二次剩余时, k = k0, 否则 k = N - k0 <br>
所以 Ry' 总是p的二次剩余 <br>

