# アーキテクチャ

この文書では、`mmt2ts`、`mmtcut`、`ts2mmt`の構成と、処理を内部パッケージへ
分ける基準を説明します。個々のバイナリ形式については
[MMT復元用DSM-CC保存形式](dsmcc-preservation-format.md)も参照してください。

## 基本方針

`mmt2ts`は、MMT/TLVから一般的なMPEG-2 TSを作るだけでなく、TSへ直接写せない
情報を同じ出力内へ保存します。通常のプレイヤーは映像、音声、字幕だけを再生でき、
`ts2mmt`は保存情報も使ってMMT/TLVを再構成できます。

実装では次の境界を守ります。

- パーサは入力を解釈するだけで、出力形式を直接生成しない
- 状態管理は断片の到着途中にある不完全な版を公開しない
- メディアの再構成とTSの多重化を分ける
- 通常TSへ変換した情報、保存カルーセルへ残した情報、失われた情報を区別する
- 逆変換側は、変換側とは別の読み取り処理で保存形式を検証する
- 入力バッファを再利用しても、後段が必要とするデータの所有権を失わない

この分離により、パケット欠落、順序変更、MPT更新、時刻の不連続をパッケージ単位で
テストできます。

## コマンド

| コマンド | 役割 |
| --- | --- |
| `mmt2ts` | MMT/TLVからTSへの変換、入力の解析、生成TSの検証 |
| `mmtcut` | 入力先頭のNTPサンプルからの経過時間でTLVを切り出す |
| `ts2mmt` | TSと保存カルーセルからMMT/TLVを再構成 |

## MMTからTSへの流れ

```text
TLV byte stream
  │
  ├─ tlv: packet同期、IP/圧縮IP展開、UDP flow分離
  │
  ├─ mmtp: MMTP headerとpayloadの解析
  │    ├─ signaling: PA messageの再構成、PLT/MPTの解析
  │    ├─ si: M2 sectionの収集とMMT-SI状態の更新
  │    └─ mpu: 分割されたmedia data unitの再構成
  │
  ├─ remux
  │    ├─ codec: HEVC/AACのTS向け変換
  │    ├─ caption: ARIB-TTMLからARIB STD-B24字幕PESへの変換
  │    ├─ siconv: MMT-SIからTS PSI/SIへの意味変換
  │    ├─ appdata: データ放送資源と参照関係の収集
  │    ├─ preservation: 未変換情報と逆変換情報の保存
  │    └─ timeline: PTS、DTS、PCRの生成
  │
  ├─ pes: access unitのPES化
  └─ mpegts: PSI/SI、PES、DSM-CC sectionのTS多重化
```

### TLVとIP

`internal/tlv`は同期バイトを探し、連続するパケットを検証して入力位置を回復します。
IPv4、IPv6、圧縮IPの状態をflowごとに持ち、後段には復元済みのUDP payloadを渡します。
NTP flowはメディアflowと分離して時刻処理へ送ります。

### MMTPとシグナリング

`internal/mmtp`は固定ヘッダ、拡張ヘッダ、payload typeを解析します。メディアpayloadは
`internal/mpu`へ、シグナリングpayloadは`internal/signaling`へ渡します。

PA messageは複数パケットに分割されるため、全断片が揃ったものだけをPLT/MPTとして
公開します。MPTからはasset type、packet ID、component tag、時刻記述子などを取得し、
`internal/remux`が出力PIDとの対応を管理します。

### MMT-SI

`internal/si`はM2 sectionをバージョンごとに収集します。同じtableの新しい版が途中までしか
届いていない間は、直前の完全な版を利用し続けます。

`internal/siconv`はNIT、SDT、EIT、TOT、BIT、CDTと各記述子をTS側の表現へ写します。
単なるバイト置換ではなく、識別子の幅や文字コード、記述子の配置差を吸収します。
TSで表現できない情報は変換済みとせず、保存または損失として記録します。

### SIの変換範囲

MMT-SIは、M2 section messageとM2 short section messageから取り出します。CRCを確認し、
table ID、extension、version、section番号をキーに全sectionが揃ってから現在版として公開します。
新しい版が途中までしか届いていない間や`current_next_indicator`がnextの間は、現在版を
置き換えません。同じsection番号で内容が食い違う重複もエラーとして数えます。

#### 出力するtable

`mmt2ts`の出力はARIB full TSです。partial TS用のSITとDITは生成しません。

| TS table | PID | 入力 | 変換内容 |
| --- | ---: | --- | --- |
| PAT | `0x0000` | 選択serviceとPMT | programとPMT、利用可能ならNITへの参照 |
| PMT | 指定または割当 | MPTと実際に出力できたasset | PCR PID、ES PID、stream type、component tag、ES記述子 |
| NIT actual | `0x0010` | 自ネットワークTLV-NIT | network ID、stream loop、対応するTLV記述子 |
| SDT actual | `0x0011` | MH-SDT actual | service ID、schedule/present flags、running status、free CA、記述子 |
| EIT p/f actual | `0x0012` | MH-EIT p/f | section 0と1、event ID、開始時刻、時間、状態、記述子 |
| EIT schedule actual | `0x0012` | MH-EIT schedule | tableの時間帯を維持し、3時間segment内を開始時刻順に再配置 |
| TOT | `0x0014` | MH-TOT | JST時刻とlocal time offset記述子 |
| BIT | `0x0024` | MH-BIT | broadcaster loopとSI parameter等の記述子 |
| CDT | `0x0029` | MH-CDT | download data ID、logo module、記述子 |

EIT p/fは入力がまだない場合も空のsection 0と1を出し、取得後に版を更新します。scheduleは
MMT側のtable IDをTS側の`0x50`–`0x5f`へ対応させ、各segmentで8 sectionに収まらないeventを
診断します。scheduleの`running_status`は未定義値にします。

MH-SDT other、TLV-NIT other、MH-SIT、MH-DIT、MH-AIT、DDMT、DAMT、DCCT、EMTも入力として
解析・収集しますが、full TSの同名tableへは出力しません。MH-AITとデータ伝送tableは
データ放送資源の参照解決に使い、元sectionは保存カルーセルへ残します。未知tableや未知messageも
件数を報告し、保存カルーセルが有効ならraw signallingとして保持します。

#### 記述子

MH記述子はbodyをそのままTSへコピーせず、一度意味を読み取ってTSの構文で作り直します。
現在、次の変換を実装しています。

| 入力記述子 | 主な出力先 | 保持・変換する内容 |
| --- | --- | --- |
| MH-short event | EIT | 言語、番組名、短文 |
| MH-extended event | EIT | itemと本文。TSの長さへ収まるよう複数記述子へ分割 |
| MH-service | SDT | service type、provider名、service名 |
| MH-video component | EIT | 解像度・aspect ratioからcomponent typeを生成し、出力済み映像tagへ接続 |
| MH-audio component | EIT | component type、simulcast group、flags、最大2言語、説明文、実ESのAAC方式 |
| MH-content | EIT | genreとuser nibble |
| MH-parental rating | EIT | 国コードとrating |
| MH-series | EIT | series ID、再放送区分、話数、番組名 |
| MH-event group | EIT | 同一出力内のevent関係。other-network groupは変換しない |
| digital copy control | PMT・EIT等 | 録画制御、最大bitrate、component別制御 |
| MH-component group | EIT | multiview等のgroup。出力にないcomponentは除外して報告 |
| MH-logo transmission | SDT | logo ID、version、download data IDまたは文字列 |
| MH-broadcaster name | BIT | 放送事業者名 |
| MH-data component | PMT ES | data component IDと追加情報 |
| MH-local time offset | TOT | 地域、offset、変更時刻、次のoffset |
| MH-SI parameter | BIT | 対応するTS table IDと送出パラメータ |
| TLV network name | NIT | network名 |
| TLV service list | NIT | service IDとservice type |
| TLV system management | NIT | system management IDと追加情報 |

stream identifierは、MPTのcomponent tagと実際にPMTへ載せたESの対応から別途生成します。
MH stream identifierのbodyはコピーしません。stuffing、identity照合専用記述子、緊急情報、
content usage control、衛星・ケーブルdelivery system、remote control key、未知記述子は
現在のTS記述子へ推測変換しません。変換不能・構文不正・変換済みをtagごとにレポートし、
元の記述子を含むsectionは保存カルーセルへ残します。

SI文字列はUTF-8からARIB 8単位符号へ再符号化します。ASCII、日本語、追加記号を扱い、
互換文字の正規化と明示的な代替文字列も適用します。記述子の長さ上限を超えた文字列は
文字境界で切り、切り詰めた文字数を報告します。標準変換、正規化、代替、DRCS、変換不能、
切り詰めをそれぞれ集計するため、変換できない文字を無言で落としません。

### メディア

`internal/mpu`が扱うのはMMTPのdata unit境界までです。実際の放送では伝送ヘッダの
sample番号やoffsetだけでaccess unit境界を確定できない場合があるため、HEVC NALやAAC
AudioMuxElementを理解する`internal/remux`が最終的な境界を決めます。

映像と音声は再符号化しません。

- HEVCは、MMT sample内の32 bit長付きNALを検証し、各NALへstart codeを付けてAnnex Bへ変換する
- AACは、MMT MFU内のLATM `AudioMuxElement`から設定とAAC raw dataを読み、通常音声をADTSへ変換する
- 22.2chなどADTSで表せない音声は、`AudioMuxElement`へLOASヘッダを付けてLATM/LOASで出力する
- 不完全なaccess unitは通常PESへ出力しない
- 映像は欠落後のrandom access pointから安全に再開する

PIDは、放送TLVのMPTに含まれるcomponent tagを基に、ARIB放送TSで用いるPID帯へ
写像します。PMTへ載せるのは、完全なclear PESを少なくとも1個生成できたassetだけです。

## アセットと識別子の対応

MMTのassetは、asset type、asset ID、packet ID、16 bitのcomponent tagで識別されます。
`mmt2ts`は放送TLVのcomponent tagを、ARIB放送TSのPID配置と8 bitのcomponent tagへ
決定的に写像します。MPTの並び順や、その時点のstream本数から番号を決めることはありません。

TSのcomponent tagには、MMT component tagの下位8 bitを優先して使います。たとえば
MMT tag `0x0010`の音声はTS tag `0x10`になります。この値が同じprogram内ですでに
使われている場合だけ、次の空きtagを割り当てます。一度割り当てた代替tagも変更しません。

このため、放送中のMPT更新で映像や音声が追加・削除されても、同じcomponent tagを持つ
assetは同じPIDとTS component tagへ変換されます。streamの増減によって既存streamが前詰めされ、
PIDの意味が入れ替わることはありません。

### 基本の写像

先頭のMMT packageは、放送TLVのcomponent tagを次の規則でARIB放送TSのPIDへ写します。
入力のtagが運用範囲外にある場合や、算出したPIDがPMTや別のESと衝突する場合だけ、
同じ用途の位置から空きPIDを探します。追加packageには重ならない別のPID帯を使います。

| MMT asset | MMT component tag | 優先TS PID | TS component tag | stream type |
| --- | ---: | ---: | ---: | ---: |
| `hev1` / `hvc1` 主映像 | `0x0000` | `0x1011` | `0x00` | `0x24` |
| 追加の`hev1` / `hvc1` | `0x0001`–`0x000f` | `0x1011 + tag` | tag下位8 bit | `0x24` |
| `mp4a` | `0x0010`–`0x0017` | `0x1100 + (tag - 0x10)` | tag下位8 bit | 通常`0x0f` |
| `stpp`字幕・文字スーパー | `0x0030`–`0x003f` | `0x1200 + (tag - 0x30)` | tag下位8 bit | `0x06` |
| realtime保存カルーセル | ― | `0x1d00` | `0xe0` | `0x0b` |
| object保存カルーセル | ― | `0x1d01` | `0xe1` | `0x0b` |

通常のAACはADTSへ変換してstream type `0x0f`とします。7.1ch以上の音声ストリーム(22.2ch音声など)のようにADTSで表現できない音声は
LATM/LOASを維持し、stream type `0x11`を使います。範囲外のcomponent tagや重複があっても
固定式を無理に適用せず、空いているPIDとtagを割り当てます。

### PMT更新

MPTにassetが載っただけではPMTへ追加しません。そのassetから完全なclear access unitを
再構成し、最初のPESを出力できた時点でPIDとcomponent tagを確定してPMTを更新します。
全期間が暗号化または不完全なassetは通常ESへ載せず、保存カルーセルが有効なら元packetを
そちらへ残します。

assetがMPTから消えたときはPMTのcurrentなESから外します。同じcomponent tagのassetが再び
現れれば規定の写像から同じPIDが得られるため、構成変更の前後でも識別子が安定します。

### 字幕とデータ放送

`internal/caption`は字幕MFUを組み立て、ARIB-TTMLの時刻、領域、文字装飾、外部資源を
読み取ります。TSで表せる本文はARIB STD-B24字幕データグループへ変換し、画像、fontなどの付随資源は
保存カルーセルへ残します。

#### TTML字幕の変換範囲

`stpp`の各MPUはsubsample番号順に組み立てます。subsample 0のTTML本文を変換対象とし、
PNG、SVG、AIFF-C PCM、MP3、AAC、SVG font、WOFF fontは外部資源として識別します。
subsampleの欠落、宣言sizeの後ろにある余分なbyte、hint listとのtype・size不一致を報告します。
保存カルーセルが有効ならTTML本文、外部資源、元MFUヘッダをobjectとして保存します。

対応するTTML名前空間はW3C TTMLと、ARIB拡張の2種類のURIです。XML prefixの名前には依存せず、
namespace URIとlocal nameで要素・属性を判定します。

| TTML要素・属性 | ARIB STD-B24字幕への変換 |
| --- | --- |
| `tt/xml:lang` | 文書の言語として解析。caption managementの言語はMMT字幕記述子から取得 |
| `ttp:frameRate` | frame指定時刻の90 kHz変換に使用 |
| `style`とstyle参照 | body、div、p、spanへ継承・上書き |
| `region`、`tts:origin`、`tts:extent` | 入力解像度から960×540字幕面へ整数scaleし、表示領域と開始位置を設定 |
| `body/div/p/span` | 1つのdivをcue、各pを同じstatement内のblockとして構成 |
| `br` | 改行制御へ変換 |
| `begin`、`end`、`dur` | cueの開始PTSと終了時の消去制御へ変換 |
| `tts:color`、`backgroundColor` | B24既定CLUTの最も近い色へ写像。完全一致か近似かを集計 |
| `tts:fontSize` | 通常・中間・小型の文字サイズへ写像。任意sizeの近似を報告 |
| `tts:textOutline` | 縁取り開始・解除と縁色へ変換。太さとblurは未対応として報告 |
| `tts:lineHeight` | 行間隔へ変換 |
| ARIB `letter-spacing` | 字間隔へ変換 |

色は8色の名前、`transparent`、`#rgb`、`#rgba`、`#rrggbb`、`#rrggbbaa`を解釈します。
既定CLUTに完全一致しない色はRGBA距離が最も近いentryへ写し、近似としてレポートします。
独自CLUT data unitは生成しません。

時刻は`HH:MM:SS`、小数秒、frame、`h`、`m`、`s`、`ms`、`f`のoffsetを90 kHzの整数値へ
変換します。割り切れない値は丸め件数を記録します。字幕のtime control modeに応じて、
MPU提示時刻、UTC起点、EITの番組開始時刻、記述子のreference時刻へcueのoffsetを加えます。
beginがないcueはMPU提示時刻を使います。NPTとtick rateを必要とする`t`単位は変換しません。

endまたはdurがあるcueは、表示時間を0.1秒単位の待ち制御へ変換した後に画面を消去します。
終了時刻がないcueは後続字幕による消去に委ね、その件数を報告します。字幕は同期PESとして
PTSを持ち、文字スーパーは非同期PESとしてPTSを付けません。caption managementは言語、DMF、
表示形式、8単位文字符号を宣言して周期送出します。

現在、次の項目はARIB STD-B24字幕へ変換しません。

- ruby、ruby位置、圏点、文字結合
- 縦書き、行揃え、文字方向、折り返し指定
- border、shadow、opacity、underline等の装飾
- 太字と斜体
- cell、em、rem単位の長さ
- paragraphだけが親divと異なる時刻を持つ構成
- TTML内のimage要素と、PNG・SVG・font・音声資源の字幕PES化
- 圧縮されたTTML文書
- NPTによる時刻制御

未対応propertyと外部資源は種類・件数・byte数を変換レポートへ出します。文字はSIと同じ
ARIB encoderで8単位符号へ変換し、標準文字、正規化、代替、DRCS、変換不能を分類します。
現在の通常変換では外部glyph sourceを設定していないため、標準文字・正規化・代替で表せない
文字はDRCSを捏造せず、変換不能文字として例を含めて報告します。

`internal/remux/appdata`はデータ放送のitem、version、hashとapplicationからの参照を
収集します。既存のデータ放送BML向けのアプリへ作り替えることはせず、元のシグナリングと資源を
逆変換またはこのカルーセルに対応したプレイヤー向けに保存します。

### 時刻

`internal/timeline`は64 bit NTP、MPU timestamp、90 kHzのPTS/DTS、27 MHz表現のPCRを
相互に対応付けます。NTPが示す放送時刻と、メディアの復号・提示時刻を区別し、最初の
有効な提示時刻をTS時間軸の基準にします。

時刻が不連続になった場合は新しいepochとして扱い、古い区間との誤った補間を避けます。
保存カルーセルにもepochとtimeline anchorを記録し、逆変換時に同じ対応を利用します。

## 保存カルーセル

`internal/preservation`は、通常TSだけではMMTへ戻せない情報を2本のDSM-CC data
carouselへ格納します。

```text
realtime carousel
  ├─ 時間区間ごとのraw signalling、CA、未変換data
  ├─ TSのAUと元MPUの対応
  ├─ codec configuration
  └─ loss report

object carousel
  ├─ application item
  ├─ TTML、画像、font、音声などの静的資源
  └─ object manifest
```

通常のTS再生系はこれらのPIDを無視できます。カルーセルの追加や破損によって映像、音声、
字幕のpayloadや時刻を変更しないことが重要な境界です。

## TSからMMTへの流れ

```text
MPEG-2 TS
  │
  ├─ tsdemux: PAT/PMT、PES、DSM-CC sectionを分離
  │
  ├─ carouselin: DII/DDBからmoduleを復元して検証
  │    └─ preservationのdecoderでmanifestとrecordを読む
  │
  ├─ tsremux
  │    ├─ codecrev: Annex B、ADTS、LATMをMMT sampleへ戻す
  │    ├─ siup: TS PSI/SIをMMT-SIへ変換
  │    ├─ mmtwrite: MMTP packetを生成
  │    └─ tlvwrite: IP/UDPとTLV packetを生成
  │
  └─ MMT/TLV byte stream
```

保存カルーセルがある場合は、raw signalling、元asset identity、MPU対応、字幕資源などを
優先して利用します。入力は`mmt2ts`が生成したTSに限定しません。保存カルーセルを持たない
ARIB準拠のHEVC放送TSでも、clearなHEVC/AACとPSI/SIから新しいMMT/TLVを構成できます。
MPEG-2 VideoなどHEVC以外の映像を含む放送TSは、この一般TS入力経路の対象外です。

保存カルーセルを持たないARIB準拠のMPEG-2 TS放送では、通常のHEVC/AAC PESだけをMMTへ
取り込みます。ARIB STD-B24字幕PESを`stpp`字幕へ逆変換する処理はなく、字幕はドロップされます。字幕を復元できるのは、
`mmt2ts`が字幕資源を独自カルーセルへ保存したTSを入力した場合です。

逆変換の目標は意味的な等価性です。元入力と同じパケット境界、圧縮IPの配置、FEC、null
packet、sequence番号の再現は求めません。ただし、保存されたraw MMTP packetは変更せず、
それ以外の伝送ヘッダは新しく生成します。

## 検証と異常時の扱い

`internal/tscheck`は、TS writerと実装を共有せずに生成結果を読み返します。PAT/PMT、CRC、
continuity counter、PCR間隔、PES長、PTSの単調性、DSM-CC moduleと参照関係を検査します。

異常時は次のように局所化します。

- TLV同期を失った場合は次の確実な境界から再開する
- sectionの新しい版が不完全なら、直前の完全な版を維持する
- access unitが欠けた場合は、そのunitを通常ESへ出さない
- 保存moduleが欠けた場合は、対応する区間またはobjectだけを利用不能にする
- 保存カルーセルの欠落を通常ESのdiscontinuityへ波及させない

変換レポートは、入力破損、未対応、暗号化、容量超過、参照未解決などを区別します。

## パッケージ配置

共有する形式処理は`internal`直下に置き、一方向だけで使う処理は変換パッケージの配下へ
置きます。

| パッケージ | 責務 |
| --- | --- |
| `internal/tlv` | TLV、IP、UDPの読み取り |
| `internal/mmtp` | MMTPヘッダとpayloadの解析 |
| `internal/signaling` | PA message、PLT、MPT |
| `internal/si` | MMT-SI sectionと版管理 |
| `internal/mpu` | MFU断片の再構成 |
| `internal/arib` | ARIB文字コードと字幕データ |
| `internal/caption` | TTMLと字幕PES |
| `internal/codec` | 長さ付きHEVCからAnnex B、LATM AACからADTSまたはLOASへの変換 |
| `internal/timeline` | NTP、PTS、DTS、PCR |
| `internal/pes` | PES生成 |
| `internal/mpegts` | TS packetとPSI/SI生成 |
| `internal/preservation` | 復元moduleとDSM-CC carousel |
| `internal/remux` | MMTからTSへのパイプライン |
| `internal/remux/appdata` | 順変換専用のデータ放送処理 |
| `internal/tsdemux` | TSの読み取り |
| `internal/tsremux` | TSからMMTへのパイプライン |
| `internal/tsremux/*` | 逆変換専用のreaderとwriter |
| `internal/tscheck` | 生成TSの独立検証 |
| `internal/inspect` | MMT/TLV入力の概要解析 |

この配置により、共有処理と変換方向固有の処理をimport pathから判別できます。
