# tokenization for bch
基于BCH实现发Token的功能  
实现的思路是把Token的内容放在BCH脚本中, 依附在交易上, 通过BCH的UTXO交易来转移Token  
扩展opcode: OP_TOKEN (OP_NOP4)  
添加rpc:
```
tokenissue  
listtokenunspent
gettokenbalance  
createtokentx  
signtokentx  
```

# tokenization example  
按照以下几步就可以实现Token的分发  

发行Token
tokenissue: 利用UTXO的txid来作为token的唯一表示符, 限制token只能发行一次, 不能增发, 使用如下:
```
./bitcoin-cli -regtest tokenissue 10000
{
  "tokenID": "1ea634ae46c012fe507cf74be794f9f0a2b103d31ec03c532e293552ef2d67c9",
  "tokenAddress": "bchreg:prc38tlqr6t5fk2nfcacp3w3hcljz4nj3sw247lksj",
  "tokenScript": "b34031656136333461653436633031326665353037636637346265373934663966306132623130336433316563303363353332653239333535326566326436376339021027757576a9140f1c285cccff07134505cf4a7a14346df16ccd8e88ac",
  "txid": "59fc480f06a0888d08bfaa63dc26c9c7b2bad51db7c479351eee3ef7a5ca5a7f"
}
```
上述命令表示发行新的token, 数量为10000个, tokenid = 1ea634ae46c012fe507cf74be794f9f0a2b103d31ec03c532e293552ef2d67c9

等待交易链之后可以用 listtokenunspent 或 gettokenbalance 查看账号中的token
```
./bitcoin-cli -regtest listtokenunspent
[
  {
    "txid": "59fc480f06a0888d08bfaa63dc26c9c7b2bad51db7c479351eee3ef7a5ca5a7f",
    "vout": 0,
    "address": "bchreg:qq83c2zuenlswy69qh8557s5x3klzmxd3cvnweu3ks",
    "scriptPubKey": "b34031656136333461653436633031326665353037636637346265373934663966306132623130336433316563303363353332653239333535326566326436376339021027757576a9140f1c285cccff07134505cf4a7a14346df16ccd8e88ac",
    "amount": 0.01000000,
    "confirmations": 1,
    "spendable": true,
    "token": "1ea634ae46c012fe507cf74be794f9f0a2b103d31ec03c532e293552ef2d67c9",
    "tokenAmount": 10000
  }
]
```
./bitcoin-cli -regtest gettokenbalance
[
  {
    "token": "1ea634ae46c012fe507cf74be794f9f0a2b103d31ec03c532e293552ef2d67c9",
    "tokenAmount": 10000
  }
]
```

交易Token
假如我想往地址 qrgs9qzgcjr9kjujzvhagvqvr8d7pypkeyzks6hvp0 上转移4000个token,  
qq5fnlc3jegdxnqt42ql6zlxykk7catx2uc5z7vw2n 上转移6000个token, 可以这么操作
```
./bitcoin-cli -regtest createtokentx '[{"txid":"59fc480f06a0888d08bfaa63dc26c9c7b2bad51db7c479351eee3ef7a5ca5a7f","vout":0}]' 
'[{"address":"qrgs9qzgcjr9kjujzvhagvqvr8d7pypkeyzks6hvp0","amount":"0.005","tokenamount":"4000","tokenname":"1ea634ae46c012fe507cf74be794f9f0a2b103d31ec03c532e293552ef2d67c9"}, 
{"address":"qq5fnlc3jegdxnqt42ql6zlxykk7catx2uc5z7vw2n","amount":"0.0049","tokenamount":"6000","tokenname":"1ea634ae46c012fe507cf74be794f9f0a2b103d31ec03c532e293552ef2d67c9"}]'
```   
接着对createtokentx的交易进行签名  
```
./bitcoin-cli signtokentx <hex>
```  
广播上链后可以调用 listtokenunspent 再次查看token  
```
./bitcoin-cli -regtest listtokenunspent
[
  {
    "txid": "447da54f27b872f0bcf955e4d716673a21b986ec8ad078fe596642f16998f361",
    "vout": 0,
    "address": "bchreg:qrgs9qzgcjr9kjujzvhagvqvr8d7pypkeyzks6hvp0",
    "scriptPubKey": "b3403165613633346165343663303132666535303763663734626537393466396630613262313033643331656330336335333265323933353532656632643637633902a00f757576a914d1028048c4865b4b92132fd4300c19dbe09036c988ac",
    "amount": 0.00500000,
    "confirmations": 1,
    "spendable": true,
    "token": "1ea634ae46c012fe507cf74be794f9f0a2b103d31ec03c532e293552ef2d67c9",
    "tokenAmount": 4000
  }
]
```
例子中的第一个地址是我的地址, 所以可以看到4000token在我的账上, 而6000token在其它人的账上  
交易token就像交易BCH一样简单 
