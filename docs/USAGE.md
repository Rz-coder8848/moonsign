# 浣跨敤鎵嬪唽

## 瀹夎

浣滀负 MoonBit 渚濊禆锛?
```sh
moon add Rz-coder8848/moonsign@0.8.0
```

浠庢簮鐮佽繍琛屽懡浠よ锛堥渶瑕?MoonBit 宸ュ叿閾撅級锛?
```sh
moon run cmd/moonsign -- help
```

## 鍛戒护鎬昏

```
moonsign sign   <in.pdf> --key <key.pem> --cert <cert.pem> [options]
moonsign verify <in.pdf> --cert <cert.pem> [--json]
moonsign verify <in.pdf> --anchors <ca.pem> [--crl <crl.pem>] [--json]
moonsign info   <in.pdf> [--json]
moonsign tsa-request <signed.pdf> --out <request.der>
moonsign tsa-embed <signed.pdf> --response <response.der> [--anchors <tsa-ca.pem>] --out <out.pdf>
```

閫€鍑虹爜锛?
| 閫€鍑虹爜 | 鍚箟 |
| --- | --- |
| 0 | 鎴愬姛锛涢獙绛鹃€氳繃锛堝甫 `--anchors` 鏃惰〃绀哄凡閾惧埌淇′换鏍癸級 |
| 2 | 楠岀澶辫触锛堟枃浠惰鏀广€佺鍚嶄笉瀵癸級 |
| 3 | 绛惧悕鏈夋晥锛屼絾璇佷功閾句笉鍙俊锛堥摼涓嶅埌鏍广€佽鍚婇攢绛夛級 |
| 1 | 鐢ㄦ硶閿欒銆佹枃浠惰鍐欏け璐ャ€佹牸寮忎笉鏀寔 |

## sign

| 鍙傛暟 | 璇存槑 |
| --- | --- |
| `--key <pem>` | 绉侀挜锛圥KCS#8 / PKCS#1 / SEC1锛屾湭鍔犲瘑锛?|
| `--cert <pem>` | 绛惧悕鑰呰瘉涔︼紙鍙跺瓙璇佷功锛?|
| `--out <pdf>` | 杈撳嚭鏂囦欢锛岄粯璁?`<杈撳叆>.signed.pdf` |
| `--chain <pem>` | 棰濆璇佷功锛堜腑闂磋瘉涔︼級锛屽彲鍖呭惈澶氬紶 |
| `--field <name>` | 绛惧悕瀛楁鍚嶏紝榛樿 `Signature1` |
| `--reason <text>` | 绛惧悕鍘熷洜锛堝啓鍏ョ鍚嶅瓧鍏革級 |
| `--location <text>` | 绛剧讲鍦扮偣 |
| `--contact <text>` | 绛剧讲浜鸿仈绯绘柟寮?|
| `--signing-time <unix>` | 鎸囧畾绛剧讲鏃堕棿锛圲nix 绉掞級锛岄粯璁ゅ綋鍓嶆椂闂?|
| `--json` | 杈撳嚭鏈哄櫒鍙缁撴灉 |

## verify

| 鍙傛暟 | 璇存槑 |
| --- | --- |
| `--cert <pem>` | 鍙鏌?绛惧悕鍜岃繖寮犺瘉涔︽槸鍚﹀尮閰?锛屼笉鍒ゆ柇淇′换 |
| `--anchors <pem>` | 缁欎竴涓垨澶氫釜淇′换鏍癸紝妫€鏌ヨ瘉涔﹂摼 |
| `--crl <pem>` | 鍚婇攢鍒楄〃锛圥EM锛屽彲鍖呭惈澶氫釜 `X509 CRL` 鍧楋級 |
| `--tsa-anchors <pem>` | 鏃堕棿鎴虫湇鍔＄殑淇′换鏍癸紱缁欎簡灏辨鏌ユ椂闂存埑璇佷功閾?|
| `--ocsp <der>` | OCSP 鍝嶅簲鏂囦欢锛涙鏌ョ鍚嶈€呰瘉涔︽槸鍚﹁鍚婇攢 |
| `--json` | 杈撳嚭鏈哄櫒鍙缁撴灉锛堝惈 `valid`銆乣trusted`銆乣chain_length`锛?|

`--cert` 鍜?`--anchors` 鑷冲皯缁欎竴涓€?
## info

鍒楀嚭 PDF 閲岀殑绛惧悕锛氬瓧娈靛悕銆乻ubfilter銆侀鐣欏瓧鑺傛暟銆乣ByteRange`銆備笉浼氶獙璇佺鍚嶃€?
## 鏃堕棿鎴筹紙B-T锛?
鏃堕棿鎴抽渶瑕佷笁鏍蜂笢瑗匡細宸茬鍚嶇殑 PDF銆佷竴涓?RFC 3161 鏃堕棿鎴虫湇鍔°€佸畠鐨勫搷搴斻€?
```sh
# 1. 鐢熸垚璇锋眰锛圖ER锛?moonsign tsa-request signed.pdf --out req.der

# 2. 鍙戦€佺粰 TSA锛堜换浣?RFC 3161 鏈嶅姟锛?curl -H "Content-Type: application/timestamp-query" \
  --data-binary @req.der https://tsa.example/ -o resp.der

# 3. 宓屽叆鍝嶅簲锛?-anchors 鍙€夛細楠岃瘉 TSA 璇佷功閾句笌 timeStamping 鐢ㄩ€旓級
moonsign tsa-embed signed.pdf --response resp.der --anchors tsa-ca.pem --out stamped.pdf
```

`tsa-embed` 浼氬厛妫€鏌ュ搷搴旈噷鐨勬椂闂存埑鏄惁瀵瑰簲杩欎唤绛惧悕锛屽啀鍐欒繘 PDF锛涚粰浜?`--anchors` 杩樹細楠岃瘉 TSA 鐨勭鍚嶃€丒KU 鍜岃瘉涔﹂摼銆傜鍚嶅€兼湰韬笉鍙橈紝鍙鍔犳湭绛惧悕灞炴€э紙unsigned attributes锛夛紝鎵€浠ュ師鏉ョ殑绛惧悕浠嶇劧鏈夋晥銆?
楠岃瘉甯︽椂闂存埑鐨?PDF锛?
```sh
moonsign verify stamped.pdf --cert cert.pem --tsa-anchors tsa-ca.pem
```

浼氬杈撳嚭涓€琛屾椂闂存埑鐘舵€侊細`VALID and TRUSTED`銆乣VALID (TSA chain not checked)` 鎴?`INVALID`銆?
> 璇佷功閾炬牎楠屼娇鐢?PDF 閲岀殑 `signingTime`锛堟病鏈夊氨鐢ㄥ綋鍓嶆椂闂达級锛屾墍浠ヨ瘉涔﹀埌鏈熷悗锛屾棫绛惧悕涓嶄細鍥犱负"鐜板湪杩囨湡"鑰岃鎶ャ€?
## OCSP

OCSP 闇€瑕佸厛鎷垮埌鍝嶅簲鏂囦欢锛圖ER锛夛細

```sh
moonsign verify signed.pdf --anchors root-ca.pem --ocsp ocsp-response.der
```

浼氭鏌ュ搷搴旂鍚嶃€佹湁鏁堟湡銆佽瘉涔﹀尮閰嶏紝骞惰緭鍑?`OCSP: good` / `OCSP: REVOKED at <鏃堕棿>` / `OCSP: unknown`銆傝鍚婇攢鏃堕€€鍑虹爜涓?3銆?
## 甯歌闂

**"绛惧悕鏈夋晥"鍒板簳璇存槑浠€涔堬紵**

璇存槑涓や欢浜嬶細鏂囦欢閲岀鍚嶇殑瑕嗙洊鑼冨洿娌℃湁琚敼杩囷紱绛惧悕鍊艰兘鐢ㄤ綘缁欑殑璇佷功楠岃瘉閫氳繃銆?
**鎬庝箞鍒ゆ柇绛惧悕鑰呭彲淇★紵**

鐢?`--anchors` 缁欏嚭浣犱俊浠荤殑鏍硅瘉涔︺€傜▼搴忎細妫€鏌ワ細璇佷功閾俱€佹湁鏁堟湡銆丆A 璧勬牸銆並eyUsage銆佽矾寰勯暱搴︼紝浠ュ強鍙€夌殑 CRL 鍚婇攢銆?
**璇佷功琚悐閿€浜嗘€庝箞鍔烇紵**

鐢?`--crl` 缁欏嚭绛惧彂鏈烘瀯鍙戝竷鐨?CRL銆傝鍚婇攢鏃朵細杈撳嚭 `VALID but NOT TRUSTED`锛屽師鍥犲啓 `certificate has been revoked`銆?
**涓轰粈涔堜笉鑳界粰宸叉湁绛惧悕鐨?PDF 鍐嶅姞涓€涓鍚嶏紵**

0.x 閲囩敤"鏁寸瘒閲嶅啓"鐨勬柟寮忚閬?PDF 澧為噺鏇存柊鐨勫吋瀹归棶棰橈紝鎵€浠ュ凡鏈夌鍚嶄細澶辨晥銆傝繖涓€鐐逛細鍦ㄥ悗缁増鏈В鍐炽€?
## 鍦ㄤ唬鐮侀噷浣跨敤

```moonbit
let options : @pades.SignOptions = {
  field_name: "Signature1",
  contents_chars: 16384,
  signing_time: Some(1793793600L),
  reason: Some("approved"),
  location: None,
  contact: None,
  hash: @crypto.Hash::Sha256,
}
let signed = @pades.sign_pdf(pdf, key, cert, [], options)

// 鍙獙绛惧悕
let ok = @pades.verify_pdf(signed, cert)

// 楠岀鍚?+ 璇佷功閾?let outcome = @pades.verify_pdf_with_anchors(signed, [root], now)
```

## 闄愬埗

- 闀挎湡楠岃瘉锛圔-LT锛夋湭瀹炵幇锛汢-T 鏃堕棿鎴抽€氳繃 `tsa-request` / `tsa-embed` 鏀寔锛堥渶鑷 TSA锛夛紱
- 涓嶆敮鎸佸姞瀵?PDF锛?- 涓嶆敮鎸佸凡鏈夌鍚嶇殑 PDF 杩藉姞绛惧悕锛?- 鍙敮鎸?RSA PKCS#1 v1.5銆丒CDSA P-256 涓?SHA-256锛圧SA 涔熸敮鎸?SHA-384/512锛夈€?