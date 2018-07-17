# tokenization for bch
基于BCH实现发Token的功能  
实现的思路是把Token的内容放在BCH脚本中, 依附在交易上, 通过BCH的UTXO交易来转移Token  
扩展opcode: OP_TOKEN (OP_NOP4)  
添加rpc:
```
tokenissue  
createtokenscript  
createtokentx  
signtokentx  
gettokenbalance  
listtokenunspent
```

# tokenization example  
按照以下几步就可以实现Token的分发  
1. 创建Token脚本  
脚本内容是:
```
OP_TOKEN <tokenname> <tokensupply> OP_DROP OP_DROP OP_DUP OP_HASH160 <pubkey> OP_EQUALVERIFY  
OP_CHECKSIG
```  
比如我想发代号为gon的代币10000个
```
./bitcoin-cli createtokenscript gon 10000  
{  
"address": "pzvcadtl6epnjenp4n6gvzum8tjp7gu5ng0ehkh2ps",  
"token": "b303676f6e021027757576a914c8ad0da40b0ff475cd749a3aa455f5af3dc3f0f388ac"  
}
```
2. 向Token脚本中打BCH
```
./bitcoin-cli sentoaddress pzvcadtl6epnjenp4n6gvzum8tjp7gu5ng0ehkh2ps 1
```  
交易上链后就实现了Token的发行, 在这个例子中地址 pzvcadtl6epnjenp4n6gvzum8tjp7gu5ng0ehkh2ps 内有10000个gon, 同时  
也有1个BCH 
 
3. 查看Token数量  
gettokenbalance 和 listtokenunspent 是用来查看Token的rpc
```
./bitcoin-cli gettokenbalance  
[  
{  
 "token": "gon",  
 "tokenAmount": 10000  
}  
]  

./bitcoin-cli listtokenunspent  
[  
{  
 "txid": "d1ed9b0b375e39859266a31d6f89d12a1b8371f6a8a9159323bcfac57d54892d",  
 "vout": 0,  
 "address": "bchreg:pzvcadtl6epnjenp4n6gvzum8tjp7gu5ng0ehkh2ps",
 "scriptPubKey": "a914998eb57fd643396661acf4860b9b3ae41f23949a87",  
 "redeemScript": "b303676f6e021027757576a914c8ad0da40b0ff475cd749a3aa455f5af3dc3f0f388ac",  
 "satoshi": 100000000,  
 "amount": 1.00000000,  
 "confirmations": 1,  
 "spendable": true,  
 "token": "gon",  
 "tokenAmount": 10000  
}  
]
```  
4. 交易Token  
假如我想往地址 qq493drnameufw7t2wc40tk57clut83gcg02aek8nm 上转移4000个gon,  
qzrsn9dhyvpgcwvrc28vkaylqee47amnacp2mt6ayp 上转移6000个gon, 可以这么操作
```
./bitcoin-cli createtokentx  
'[{"txid":"d1ed9b0b375e39859266a31d6f89d12a1b8371f6a8a9159323bcfac57d54892d","vout":0}]'  
'[{"address":"qq493drnameufw7t2wc40tk57clut83gcg02aek8nm","amount":"0.5","tokenamount":"4000","tokenname":"gon"},  
{"address":"qzrsn9dhyvpgcwvrc28vkaylqee47amnacp2mt6ayp","amount":"0.49","tokenamount":"6000","tokenname":"gon"}  
]'
```   
接着对createtokentx的交易进行签名  
```
./bitcoin-cli signtokentx <hex>
```  
广播上链后可以调用listtokenunspent再次查看token  
```  
./bitcoin-cli listtokenunspent  
[  
 {  
 "txid": "e563405c43f28cbde89269de89eed3c045792917a9ad6e0686eca91b0d1bafcc",  
 "vout": 0,  
 "address": "bchreg:qq493drnameufw7t2wc40tk57clut83gcg02aek8nm",  
 "scriptPubKey": "b303676f6e02a00f757576a9142a58b473eef3c4bbcb53b157aed4f63fc59e28c288ac",  
 "satoshi": 10000000,  
 "amount": 0.10000000,  
 "confirmations": 1,  
 "spendable": true,  
 "token": "gon",  
 "tokenAmount": 4000  
 }  
]
```  
例子中的第一个地址是我的地址, 所以可以看到4000gon在我的账上, 而6000gon在其它人的账上  
重复第4步就可以像BCH交易一样转移Token 

5. tokenissue
新增RPC:tokenissue, 优化了发行token的流程, 利用UTXO的txid来作为token的唯一表示符
限制token只能发行一次, 不能增发, 使用如下:
```
./bitcoin-cli tokenissue 22222
{
  "tokenID": "7601c731fc928b6cf43548f6f70b829f4a372f0f6c85ffa45e5ed52c4cc3af1a",
  "tokenAddress": "bchreg:pqt8fn4dr03sprrnw69tj2ggyw657v8z4g0w64xmmd",
  "tokenScript": "b3403736303163373331666339323862366366343335343866366637306238323966346133373266306636633835666661343565356564353263346363336166316102ce56757576a914dea243dcc8b4edbe88039aae76ea12d51ffbc34488ac",
  "txid": "bdacd6045768a02a05f463b493b71167ae2a75484e11801734c8ef75d97242bd"
}
```



 
  
