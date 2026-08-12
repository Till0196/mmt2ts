# MMT復元用DSM-CC保存形式

この文書は、`mmt2ts`がMPEG-2 TSへ格納し、`ts2mmt`が読み戻す復元用データの
version 1形式を説明します。実装は`internal/preservation`にあります。

この形式の目的は、通常のTSでは表現できないMMT固有情報と、TSからMMTへ戻す際に
不足する情報を、映像・音声・字幕と同じTS内へ保存することです。通常のTSプレイヤーは
保存PIDを無視でき、対応readerだけがmodule内の`MMTC`形式を解釈します。

元のTLVとバイト単位で一致させる形式ではありません。元のpacket境界、圧縮IP、FEC、
null packet配置は保存対象外です。一方、rawとして保存したMMTP packetやsignallingは、
元のbyte列を変更せずに保持します。

## 1. 全体構成

1つのprogramにつき、用途の異なる2本のDSM-CC data carouselを使用します。

| role | 優先PID | component tag | 主な内容 |
| --- | ---: | ---: | --- |
| realtime | `0x1d00` | `0xe0` | 時間区間、codec設定、AV対応、loss |
| object | `0x1d01` | `0xe1` | 静的資源、object目録 |

PIDまたはcomponent tagが使用済みなら空いている値を割り当てます。割り当て後は同じ変換中に
変更しません。PMTでは両方とも`stream_type=0x0b`とし、stream identifier descriptorを
付けます。既存のdata component IDを独自形式の識別へ流用しません。

各carouselの識別子はservice IDを含みます。

```text
realtime downloadId = 0x4d520000 | service_id
object   downloadId = 0x4d530000 | service_id
```

対応readerはPMTだけで独自形式と決めつけず、DII/DDB、download ID、module先頭の`MMTC`、
major version、service identityを合わせて確認します。

## 2. DSM-CCによるmodule伝送

moduleはDIIで一覧とサイズを通知し、DDBで最大4066 byteずつ送ります。DIIとDDBは
MPEG-2のlong sectionとしてCRC付きで伝送されます。

| 項目 | 値 |
| --- | ---: |
| DII `table_id` | `0x3b` |
| DDB `table_id` | `0x3c` |
| DII `messageId` | `0x1002` |
| DDB `messageId` | `0x1003` |
| `protocolDiscriminator` | `0x11` |
| download用`dsmccType` | `0x03` |
| block size | 4066 byte |
| 最大block数 | 256 |
| 最大module size | 1,040,896 byte |
| 最大module数 | 256 |

DDBの`table_id_extension`はmodule ID、section versionはmodule versionの下位5 bit、
`section_number`はblock番号です。block番号は0から始まり、最後以外のblockは4066 byteに
なります。1 moduleを256 block以内に制限するため、section番号はwrapしません。

DIIのtransaction IDは上位2 bitを`10`とし、下位30 bitを更新番号に使います。moduleの集合、
size、versionが変わったときだけ更新します。DIIには次のmodule entryを並べます。

```text
moduleId:u16
moduleSize:u32
moduleVersion:u8
moduleInfoLength:u8 = 0
```

`moduleSize`には後述する48 byteの共通ヘッダを含めます。0 byteのmoduleは認めません。

readerは、先にcurrent DIIを取得し、そこに載っているmodule IDとversionのDDBだけを集めます。
全blockを連結した長さがDIIの`moduleSize`と一致しなければ、そのmoduleを破棄します。

## 3. module ID

### realtime carousel

| 範囲 | 内容 |
| --- | --- |
| `0x0000` | bootstrap manifest |
| `0x0100`–`0x013f` | 16区間×最大4 partのtimed segment |
| `0x0200`–`0x020f` | 16 slotのloss report |
| `0x0300` | current codec configuration |
| `0x0301` | current AV MPU map |

timed segmentのmodule IDは次の式で決まります。

```text
0x0100 + (segment_sequence mod 16) * 4 + part_number
```

### object carousel

| 範囲 | 内容 |
| --- | --- |
| `0x0000` | bootstrap manifest |
| `0x0001` | current object manifest |
| `0x0100`–`0x01fd` | static objectを格納するmodule |

同じmodule IDへ新しい内容を入れるときはmodule versionを1増やします。古いDDBが新しい
moduleへ混ざらないよう、退役したID/versionの組は少なくとも10秒間再利用しません。

## 4. MMTC共通ヘッダ

全moduleは48 byteの共通ヘッダから始まります。整数はすべてunsigned big-endianです。
明記しないreserved領域は0で書きます。

| offset | size | field | 説明 |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | ASCII `MMTC` |
| 4 | 1 | major version | version 1は`1` |
| 5 | 1 | module kind | payloadの種類 |
| 6 | 2 | flags | module状態 |
| 8 | 4 | epoch ID | 時刻の不連続単位 |
| 12 | 2 | header length | version 1は`48` |
| 14 | 2 | reserved | 0 |
| 16 | 8 | logical ID | kindごとの論理識別子 |
| 24 | 8 | start NTP | 対象区間がなければ0 |
| 32 | 4 | duration ms | 対象区間がなければ0 |
| 36 | 4 | payload length | 共通ヘッダを除く長さ |
| 40 | 4 | payload CRC | CRC-32/ISO-HDLC |
| 44 | 4 | header CRC | このfieldを0として計算 |

CRCはGoの`crc32.ChecksumIEEE`と同じものです。DSM-CC section末尾のCRCとは別に検証します。

flagsは次の3 bitだけを定義します。

| bit | 名称 | 意味 |
| ---: | --- | --- |
| `0x0001` | incomplete | 内容の一部が欠けている |
| `0x0002` | raw exact | 元byte列をそのまま保持している |
| `0x0004` | commit | object集合を利用可能にするmanifest |

commitは`OBJECT_MANIFEST`だけに設定でき、incompleteとの併用は禁止します。

## 5. module kind

| 値 | 名称 | 役割 |
| ---: | --- | --- |
| `0x01` | `BOOTSTRAP_MANIFEST` | serviceと現在のmodule一覧 |
| `0x02` | `TIMED_SEGMENT` | 時間区間内のsignallingとdata |
| `0x03` | `STATIC_OBJECT` | application itemや字幕資源のbyte列 |
| `0x04` | `OBJECT_MANIFEST` | objectの分割位置、hash、世代 |
| `0x05` | `CODEC_CONFIG` | HEVC/AACの逆変換に必要な設定 |
| `0x06` | `AV_MPU_MAP` | TSのAUと元MMT asset/MPUの対応 |
| `0x07` | `LOSS_REPORT` | 保存・復元できなかった情報 |

`epoch_id`はrealtime moduleでは現在のepoch、object moduleでは`0xffffffff`です。
`logical_id`はmodule IDとは別の識別子で、segment sequence、object pack、manifest更新、
report sequenceなどを表します。kindが異なるlogical IDを同じ名前空間として扱いません。

## 6. Bootstrap manifest

bootstrapは、途中から受信したreaderが現在必要なmoduleを見つけるための小さな目録です。
payloadの固定部分は次の順序です。

```text
service_id:u16
transport_stream_id:u16
original_network_id:u16
epoch_id:u32
generation:u32
update_number:u32
segment_duration_ms:u32
lead_time_ms:u16
playout_limit_ms:u16
realtime_download_id:u32
object_download_id:u32
latest_complete_segment:u64
entry_count:u16
reserved:u16 = 0
entry[entry_count]
```

各directory entryは78 byteです。

```text
carousel_role:u8
required:u8
module_id:u16
module_version:u8
module_kind:u8
part_number:u16
part_count:u16
logical_id:u64
stored_size:u32
original_size:u64
valid_from_ntp:u64
valid_until_ntp:u64
sha256[32]
```

entryは`carousel_role, module_id`の順で昇順に並べます。bootstrap自身は一覧へ含めません。
`stored_size`は共通ヘッダを含むmodule size、SHA-256は共通ヘッダを除いたpayloadに対する値です。
`valid_until_ntp=0`は期限なしを表します。

`required=1`のmoduleが欠けている集合は利用できません。未知の任意moduleは無視できますが、
未知の必須moduleを要求する集合は復元不能として扱います。

## 7. Timed segment

realtime情報は既定500 msのNTP時間窓へ分けます。実装は入力に応じて250–1000 msを選び、
同じepoch内では変更しません。各区間は最大4 moduleへ分割できますが、1 recordをmodule境界で
分割することはありません。

payloadは次のrecord列です。

```text
record_count:u16
reserved:u16 = 0

record {
  kind:u8
  flags:u8
  metadata_length:u16
  payload_length:u32
  order:u32
  source_ntp:u64
  metadata[metadata_length]
  payload[payload_length]
}
```

`order`は0から始まる連続値です。同じ区間内の元の順序を復元するために使います。

### record kind

| 値 | 名称 | payload |
| ---: | --- | --- |
| `0x01` | `RAW_SIGNALLING` | 元messageまたはsection全体 |
| `0x02` | `CA_DATA` | CA関連のopaque byte列 |
| `0x03` | `GENERIC_TIMED_DATA` | 通常形式へ変換しない時刻付きdata |
| `0x04` | `TIMELINE_ANCHOR` | NTPとTS時刻の対応 |
| `0x05` | `OBJECT_ACTIVATION` | objectの有効化・無効化 |
| `0x06` | `LOSS` | その区間に直結する欠落情報 |

record flagsは`0x01=raw exact`、`0x02=incomplete`、`0x04=required`です。

`TIMELINE_ANCHOR`は24 byteです。

```text
output_pid:u16
clock_kind:u8
reserved:u8 = 0
pts_90k:u64
source_ntp:u64
epoch_id:u32
```

`clock_kind`はpresentation、decode、deliveryのいずれかです。

`OBJECT_ACTIVATION`は16 byteです。

```text
object_id:u64
generation:u32
action:u8
reserved[3] = 0
```

actionはactivate、deactivate、replaceを表します。

## 8. record metadata

metadataは`type:u16, length:u16, value[length]`を繰り返すTLV列です。未知typeはlengthを
使って読み飛ばせます。`related logical ID`以外のtypeは同じrecord内で重複できません。

| type | 内容 | 長さ |
| ---: | --- | ---: |
| `0x0001` | MMTP packet ID | 2 |
| `0x0002` | packet sequence | 4 |
| `0x0003` | packet counter | 4 |
| `0x0004` | asset type | 4 |
| `0x0005` | asset ID scheme | 4 |
| `0x0006` | asset ID | 可変 |
| `0x0007` | component tag | 2 |
| `0x0008` | MPU sequence | 4 |
| `0x0009` | item ID | 4 |
| `0x000a` | subtitle identity | 6 |
| `0x000b` | signalling kind | 1 |
| `0x000c` | table identity | 9 |
| `0x000d` | descriptor tag | 2 |
| `0x000e` | TLV packet type | 1 |
| `0x000f` | input byte offset | 8 |
| `0x0010` | source IP | 4または16 |
| `0x0011` | destination IP | 4または16 |
| `0x0012` | IP protocol | 1 |
| `0x0013` | UDP source port | 2 |
| `0x0014` | UDP destination port | 2 |
| `0x0015` | output PID | 2 |
| `0x0016` | output component tag | 1 |
| `0x0017` | object size | 8 |
| `0x0018` | object SHA-256 | 32 |
| `0x0019` | related logical ID | 8、反復可 |
| `0x001a` | application identity | 8 |
| `0x001b` | UTF-8 path | 可変 |
| `0x001c` | UTF-8 media type | 可変 |
| `0x001d` | 元字幕MFUヘッダ | 可変 |

暗号化されたESのMMTP packetは`GENERIC_TIMED_DATA`として保存します。この場合、media typeを
`application/mmtp`、payloadを完全なMMTP packet 1個とし、raw exactとrequiredを設定します。
TLV/IP/UDPヘッダや複数packetを同じpayloadへ含めません。

## 9. Static objectとObject manifest

`STATIC_OBJECT`はobjectの格納byte列だけを持ち、内部に独自の境界ヘッダを置きません。
境界、圧縮、分割順序、hashの正本は`OBJECT_MANIFEST`です。小さいobjectは同じmoduleへ
詰め合わせ、大きいobjectは複数moduleへ分割できます。

object manifestは次の構造です。

```text
generation:u32
update_number:u32
object_count:u32

object {
  object_id:u64
  class:u8
  flags:u8
  compression:u8
  reserved:u8 = 0
  part_count:u16
  path_length:u16
  media_type_length:u16
  metadata_length:u16
  original_size:u64
  original_sha256[32]
  path[path_length]
  media_type[media_type_length]
  metadata[metadata_length]
  part[part_count]
}

part {
  module_id:u16
  module_version:u8
  reserved:u8 = 0
  part_number:u16
  reserved2:u16 = 0
  offset:u32
  stored_length:u32
  stored_sha256[32]
}
```

classはapplication item、TTML、image、font、audio、generic asset、raw signallingを
区別します。compressionはnoneまたはzlibです。part番号は0から連続し、全partを連結して
展開した結果が`original_size`と`original_sha256`へ一致しなければなりません。

pathは仮想的なorigin内の名前です。絶対path、drive prefix、NUL、`..`による上位directory
参照を拒否し、OSのfilesystem pathとして直接扱いません。

新しいobject集合は、全required objectを検証し、commit flag付きmanifestを受信した時点で
一括して有効にします。更新途中では直前のcompleteな集合を使い続けます。

## 10. Codec configuration

`CODEC_CONFIG`は、TSのelementary streamだけではMMT sampleへ戻せない設定を保持します。

```text
entry_count:u16
reserved:u16 = 0

entry {
  config_id:u64
  asset_type[4]
  packet_id:u16
  output_pid:u16
  config_kind:u8
  flags:u8
  asset_id_length:u16
  effective_from_ntp:u64
  data_length:u32
  sha256[32]
  asset_id[asset_id_length]
  data[data_length]
}
```

config kindはHEVC configuration、AudioSpecificConfig、StreamMuxConfig、otherです。
同じassetに複数の設定がある場合は、対象NTP以前で最も新しいentryを使います。

## 11. AV MPU map

`AV_MPU_MAP`は、TSへ出したaccess unitと元のasset、packet ID、MPU sequenceを結びます。

```text
entry_count:u32

entry {
  packet_id:u16
  output_pid:u16
  asset_type[4]
  mpu_sequence:u32
  first_au_ordinal:u64
  au_count:u32
  flags:u16
  asset_id_length:u16
  start_ntp:u64
  end_ntp:u64
  asset_id[asset_id_length]
}
```

AU範囲とNTP範囲は半開区間です。entryは`start_ntp, output_pid, mpu_sequence`の順に
並べます。moduleは現在の保持窓に必要なentryだけを持ち、録画全体の累積履歴にはしません。

## 12. Loss report

保存できなかった情報を黙って捨てないため、`LOSS_REPORT`へ原因と範囲を記録します。

```text
entry_count:u32

entry {
  scope:u8
  reason:u8
  severity:u8
  flags:u8
  epoch_id:u32
  logical_id:u64
  start_ntp:u64
  end_ntp:u64
  input_offset:u64
  expected_size:u64
  received_size:u64
  message_length:u16
  metadata_length:u16
  message_utf8[message_length]
  metadata[metadata_length]
}
```

scopeはsegment、signalling、object、AV MPU、carouselを区別します。reasonは入力欠落、
構文不正、暗号化または未対応、外部資源不足、容量超過、参照未解決、変換失敗を区別します。
severityは情報のみ、一部欠落、TLV再構成不能の3段階です。

timed segment内の`LOSS`はその区間の判断に必要な即時情報、独立した`LOSS_REPORT`は
累積集計と静的objectの欠落に使います。同じ障害を両方へ記録するときは同じlogical IDを
使い、二重計上を避けます。

## 13. 検証順序

readerは外側から順に検証し、一致しない値を別の層の値で補正しません。

1. TS sectionのCRCとDII/DDBヘッダ、download IDを検証する
2. current DIIに載るID/versionの全blockを集め、module sizeを検証する
3. MMTCのmagic、version、length、header CRC、payload CRCを検証する
4. bootstrap entryがある場合はrole、ID、version、kind、size、期間、SHA-256を照合する
5. object manifestのpartがmodule内の有効範囲を指すことを検証する
6. partを連結・展開し、object全体のsizeとSHA-256を検証する
7. required objectが揃ったcommit済み集合だけを公開する

途中で失敗したmoduleと、それをrequiredとして参照する集合は利用しません。通常の映像、音声、
字幕のTS処理は継続します。

## 14. 再送と途中受信

DIIとbootstrapは短い間隔で繰り返し、timed segmentは初回送出後に再送します。静的objectは
manifestが参照している間、低い頻度で繰り返します。AV、PCR、PSI/SIを常に優先し、保存帯域が
不足しても通常ESの時刻を移動しません。

途中から受信したreaderは、DII、bootstrap、現在epochのtimeline anchor、次の完全なsegmentが
揃うまでMMT/TLV出力を待ちます。必要なpartが期限までに揃わなければ、その区間をlossとして
次へ進みます。

## 15. 逆変換で保証するもの

`ts2mmt`は次を保存情報から復元します。

- 元のraw signallingとその送出順序
- TSのaccess unitと元asset、MPU sequenceの対応
- HEVC/AACをMMT sampleへ戻すためのconfiguration
- TTML、画像、font、application itemなどの静的資源
- objectを有効化した時刻と世代
- 暗号化されたまま保持したraw MMTP packet
- 保存または変換できなかった範囲

新しく生成するMMTP、IP、UDP、TLVの伝送ヘッダは、意味を保つ範囲で組み直します。そのため
元TLVとのbyte一致は保証しませんが、通常ESのaccess unitと時刻、保存した資源、signallingの
意味が一致することを目標としています。
