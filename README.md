# MoonSign

鐢ㄧ函 MoonBit 鍐欑殑 PDF 鏁板瓧绛惧悕宸ュ叿锛?*缁?PDF 绛惧悕锛屽苟楠岃瘉瀹冩湁娌℃湁琚敼杩囥€?*

> 褰撳墠鏄?0.7 寮€鍙戠増锛屽姛鑳藉彲鐢ㄤ絾杩樹笉閫傚悎鐩存帴鐢ㄤ簬鏈夋硶寰嬫晥鍔涚殑姝ｅ紡绛剧讲銆?
## 瀹冭В鍐充粈涔堥棶棰?
鍚堝悓銆佸彂绁ㄣ€佸綍鐢ㄩ€氱煡銆佹娴嬫姤鍛婅繖绫?PDF锛屽彂鍑哄幓涔嬪悗闇€瑕佽瘉鏄庝袱浠朵簨锛?
1. 杩欎唤鏂囦欢纭疄鏄煇涓崟浣?涓汉绛剧殑锛?2. 绛惧畬涔嬪悗鍐呭娌℃湁琚敼杩囥€?
鍥介檯閫氱敤鐨勫仛娉曞彨 **PAdES**锛圥DF 鐨勬暟瀛楃鍚嶆爣鍑嗭級銆侻oonBit 鐢熸€侀噷宸茬粡鏈?PDF 瑙ｆ瀽搴撳拰瀵嗙爜瀛﹀簱锛屼絾涓棿"鎶婄鍚嶅啓杩?PDF銆佸啀楠屽洖鏉?鐨勮繖涓€灞備竴鐩寸┖鐫€銆侻oonSign 琛ョ殑灏辨槸杩欎竴灞傘€?
## 涓変釜浣跨敤鍦烘櫙

1. **鍙戝悎鍚?/ Offer**锛氫笟鍔＄郴缁熺敓鎴?PDF锛岀敤鍏徃璇佷功绛句竴娆★紝瀵规柟鐢?Adobe銆佺鏄曟垨 WPS 鎵撳紑灏辫兘鐪嬪埌"绛惧悕鏈夋晥"銆?2. **鐢靛瓙鍙戠エ / 璇佹槑褰掓。**锛氬彂甯冩椂绛句竴娆★紝鍑犲勾鍚庨噸鏂伴獙绛撅紝鑳借瘉鏄庢枃浠舵病鏈夎鏀瑰姩銆?3. **CI 浜х墿绛惧悕**锛氭瀯寤烘祦绋嬮噷鑷姩缁?PDF 鎶ュ憡绛惧悕锛屼綔涓哄彲杩芥函鐨勪氦浠樺嚟璇併€?
## 鐜板湪鑳藉仛浠€涔?
| 鑳藉姏 | 鐘舵€?|
| --- | --- |
| 绛惧悕绠楁硶 | RSA PKCS#1 v1.5銆丒CDSA P-256锛孲HA-256 |
| 绛惧悕鏍煎紡 | PAdES B-B锛坄ETSI.CAdES.detached`锛夛紝CMS SignedData锛涘彲闄勫姞 B-T 鏃堕棿鎴?|
| 楠岀 | 妫€鏌ュ瓧鑺傝寖鍥淬€佹憳瑕併€佺鍚嶏紱鏂囦欢琚敼涓€涓瓧鑺傚氨澶辫触 |
| 璇佷功閾?| `--anchors` 鎸囧畾淇′换鏍癸紝妫€鏌ョ鍚嶈€呰瘉涔﹁兘鍚﹂摼鍒板畠 |
| 鍚婇攢妫€鏌?| `--crl` 鎸囧畾 CRL锛圥EM锛夛紝鎷掔粷宸茶鍚婇攢鐨勮瘉涔?|
| OCSP | `--ocsp` 鎸囧畾 OCSP 鍝嶅簲锛圖ER锛夛紝妫€鏌ュ湪绾垮悐閿€鐘舵€?|
| 鍛戒护琛?| `sign` / `verify` / `info` |
| 浜掓搷浣?| OpenSSL 涓?pyHanko 鍙屽悜楠岃瘉锛圕I 姣忔閮借窇锛?|
| 鏃堕棿鎴?| RFC 3161锛氳姹傘€佸祵鍏ャ€佹牎楠岃瘉涔﹂摼锛圔-T锛夛紱`verify --tsa-anchors` 鍙鏌?|
| 骞冲彴 | Linux / macOS / Windows锛圕I 涓夊钩鍙拌窇娴嬭瘯锛?|
| 鍙戝竷 | mooncakes.io锛歔Rz-coder8848/moonsign@0.8.0](https://mooncakes.io/docs/Rz-coder8848/moonsign@0.8.0) |

## 蹇€熷紑濮?
浣滀负渚濊禆浣跨敤锛歚moon add Rz-coder8848/moonsign@0.8.0`銆?
鍏堝噯澶囦竴寮犵┖鐧?PDF 鍜屼竴寮犳祴璇曡瘉涔︼紙姝ｅ紡浣跨敤璇锋崲鎴愪綘鑷繁鐨勮瘉涔︼級锛?
```sh
moon run cmd/mkpdf -- blank.pdf

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=MoonSign Demo"

moon run cmd/moonsign -- sign blank.pdf --key key.pem --cert cert.pem --out signed.pdf

moon run cmd/moonsign -- verify signed.pdf --cert cert.pem

moon run cmd/moonsign -- info signed.pdf
```

绛惧悕鎴愬姛浼氱湅鍒帮細

```
Signed: signed.pdf
Field: Signature1
Digest: SHA-256
```

楠岀鎴愬姛浼氱湅鍒帮細

```
Signature 1: Signature1
  subfilter: ETSI.CAdES.detached
Result: VALID
  The document has not changed since signing.
```

濡傛灉鏈変汉鏀逛簡 PDF 閲岀殑鍐呭锛宍verify` 浼氳緭鍑?`INVALID`锛屽苟浠ラ€€鍑虹爜 2 缁撴潫锛屾柟渚胯剼鏈垽鏂€?
### 妫€鏌?杩欏紶璇佷功鏄笉鏄彲淇＄殑"

鍙湅绛惧悕锛屽彧鑳借鏄?鏂囦欢鍜岃瘉涔﹀寰椾笂"銆傝鍒ゆ柇绛惧悕鑰呮槸涓嶆槸浣犱俊浠荤殑鏈烘瀯锛岄渶瑕佺粰鍑轰俊浠绘牴锛?
```sh
# 绛惧悕鏃舵妸涓棿璇佷功涓€璧锋斁杩涘幓
moon run cmd/moonsign -- sign blank.pdf --key leaf.key --cert leaf.crt \
  --chain intermediate.crt --out chain-signed.pdf

# 楠岀鏃舵寚瀹氫綘淇′换鐨勬牴璇佷功
moon run cmd/moonsign -- verify chain-signed.pdf --anchors root-ca.crt
```

缁撴灉鏈変笁绉嶏細

- `VALID and TRUSTED`锛氱鍚嶆湁鏁堬紝涓旇瘉涔﹂摼鑳借蛋鍒颁綘缁欑殑鏍癸紙閫€鍑虹爜 0锛夛紱
- `VALID but NOT TRUSTED`锛氱鍚嶆湁鏁堬紝浣嗛摼涓嶅埌浣犵粰鐨勬牴锛堥€€鍑虹爜 3锛夛紱
- `INVALID`锛氭枃浠惰鏀硅繃鎴栫鍚嶄笉瀵癸紙閫€鍑虹爜 2锛夈€?
### 妫€鏌ヨ瘉涔︽湁娌℃湁琚悐閿€

濡傛灉绛惧彂鏈烘瀯鎶婅瘉涔︿綔搴熶簡锛屽彲浠ラ檮涓婁竴浠?CRL锛堣瘉涔﹀悐閿€鍒楄〃锛夛細

```sh
moon run cmd/moonsign -- verify signed.pdf \
  --anchors root-ca.pem --crl issuer.crl.pem
```

璇佷功琚悐閿€鏃讹紝缁撴灉浼氭槸 `VALID but NOT TRUSTED`锛屽師鍥犲啓 `certificate has been revoked`锛堥€€鍑虹爜 3锛夈€?
### 鏌?OCSP锛堝湪绾垮悐閿€锛?
OCSP 鏄彟涓€绉嶅悐閿€鏌ヨ鏂瑰紡銆侻oonSign 涓嶇洿鎺ヨ仈缃戯紝闇€瑕佸厛鎶婂搷搴斾繚瀛樻垚鏂囦欢锛堢敤 curl銆佹祻瑙堝櫒鎴栨満鏋勬彁渚涚殑宸ュ叿锛夛紝鍐嶄氦缁欏畠妫€鏌ワ細

```sh
moon run cmd/moonsign -- verify signed.pdf \
  --anchors root-ca.pem --ocsp ocsp-response.der
```

杈撳嚭浼氬涓€琛?`OCSP: good`銆乣OCSP: REVOKED at ...` 鎴?`OCSP: unknown`銆傝鍚婇攢鏃堕€€鍑虹爜涓?3銆?
### 鍔犳椂闂存埑锛圔-T锛?
鏃堕棿鎴崇敤鏉ヨ瘉鏄?杩欎釜绛惧悕鏄粈涔堟椂鍊欏仛鐨?銆侻oonSign 涓嶇洿鎺ヨ仈缃戯紝鍒嗕笁姝ワ細

```sh
# 1. 浠庡凡绛惧悕鐨?PDF 鐢熸垚鏃堕棿鎴宠姹?moon run cmd/moonsign -- tsa-request signed.pdf --out req.der

# 2. 鎶?req.der 鍙戠粰浠绘剰 RFC 3161 鏃堕棿鎴虫湇鍔★紙curl 绀轰緥锛?curl -H "Content-Type: application/timestamp-query" \
  --data-binary @req.der https://your-tsa.example/ -o resp.der

# 3. 鎶婂搷搴斿祵杩?PDF锛?-anchors 鐢ㄦ潵楠岃瘉 TSA 鐨勮瘉涔﹂摼锛?moon run cmd/moonsign -- tsa-embed signed.pdf --response resp.der \
  --anchors tsa-ca.pem --out stamped.pdf
```

绛惧悕鏈韩涓嶅彉锛屽彧鏄浜嗘椂闂存埑闄勪欢锛沗verify` 浠嶇劧閫氳繃銆傚祵鍏ュ墠浼氭鏌ユ椂闂存埑纭疄瀵瑰簲杩欎釜绛惧悕锛涚粰浜?`--anchors` 鏃惰繕浼氭鏌?TSA 璇佷功閾惧拰 timeStamping 鐢ㄩ€斻€?
楠岃瘉鏃朵篃鍙互妫€鏌ユ椂闂存埑锛?
```sh
moon run cmd/moonsign -- verify stamped.pdf --cert cert.pem --tsa-anchors tsa-ca.pem
```

杈撳嚭閲屼細澶氫竴琛?`timestamp: VALID and TRUSTED`锛堟垨 `VALID (TSA chain not checked)`锛夈€?
## 鍦ㄤ唬鐮侀噷浣跨敤

```moonbit
let signed = @pades.sign_pdf(
  pdf_bytes,
  @pades.SigningKey::Rsa(modulus, private_exponent),
  certificate,
  extra_certificates,
  {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: None,
    hash: @crypto.Hash::Sha256,
  },
)

let ok = @pades.verify_pdf(signed, certificate)
```

## 椤圭洰缁撴瀯

```
der/      DER / ASN.1 鍩虹缂栫爜锛圕MS銆佽瘉涔﹂兘闈犲畠锛?x509/     璇佷功瑙ｆ瀽銆佸叕閽ユ彁鍙?crypto/   鎽樿銆丷SA銆丒CDSA锛堝熀浜?mooncry锛?cms/      CMS SignedData 鐨勬瀯閫犮€佽В鏋愩€侀獙绛?pdf/      鍦?PDF 閲屾斁绛惧悕鍩熴€佸啓 ByteRange銆佸～绛惧悕
pades/    瀵瑰鍏ュ彛锛歴ign_pdf / verify_pdf
pem/      璇?PEM 鏍煎紡鐨勭閽ュ拰璇佷功
cmd/      鍛戒护琛岀▼搴?```

## 鐜板湪鏄庣‘涓嶅仛

- 涓嶅仛 PDF 娓叉煋/鎺掔増锛?- 涓嶅仛璇佷功棰佸彂銆佹椂闂存埑鏈嶅姟銆佷俊浠诲垪琛紙杩欎簺鏄彟涓€濂楃郴缁燂級锛?- 鏆備笉鏀寔鍔犲瘑 PDF锛?- 鏆備笉鏀寔缁?宸茬粡鏈夌鍚?鐨?PDF 杩藉姞绗簩涓鍚嶏紙璺嚎鍥鹃噷鏈夛級锛?- 0.1 鐗堟湰娌℃湁缁忚繃瀹夊叏瀹¤銆?
## 鎬庝箞楠岃瘉瀹冪湡鐨勮兘鐢?
- 浠撳簱閲岀殑 30 澶氫釜娴嬭瘯瑕嗙洊锛氱紪鐮併€佽瘉涔﹁В鏋愩€丆MS 鏋勯€?楠岀銆丳DF 绛惧悕銆佺鏀规娴嬶紱
- CI 鍦?Linux / macOS / Windows 涓婅窇娴嬭瘯锛?- CI 杩樹細鎶?MoonSign 鐢熸垚鐨?CMS 鍜?PDF 浜ょ粰 OpenSSL 楠岀锛岀‘淇濅笉鏄?鑷繁楠岃嚜宸?銆?
## 鏇村鏂囨。

- [浣跨敤鎵嬪唽](docs/USAGE.md)锛堝叏閮ㄥ懡浠や笌鍙傛暟锛?- [鏇存柊鏃ュ織](CHANGELOG.md)
- [鍏抽敭鎶€鏈喅绛朷(docs/DECISIONS.md)
- [RFC 瀵圭収琛╙(docs/RFC-MAP.md)
- [鍏煎鎬х煩闃礭(docs/COMPATIBILITY.md)
- [瀹夊叏璇存槑](docs/SECURITY.md)

## 璁稿彲璇?
Apache-2.0锛岃 [LICENSE](LICENSE)銆?