# Toy TCP/IP

Kotlinで実装したTCP/IPスタックです。教育および学習目的で作成されています。

## 特徴

- [x] ネットワークデバイス
  - [x] LinuxのTAPデバイス
  - [x] LinuxのPF_PACKETソケット
  - [ ] BSDのTAPデバイス
  - [ ] BSDのBPF
- [x] イーサネットレイヤー
- [x] ARPプロトコル
- [x] IPレイヤー
  - [x] 送信処理
  - [x] 受信処理
  - [x] フラグメンテーション
  - [x] チェックサム計算
  - [ ] ルーティング
  - [ ] パケット転送
  - [ ] IPアドレスによる動的デバイス選択
- [ ] ICMPプロトコル
- [ ] DHCPクライアント
- [x] TCPプロトコル
  - [x] ソケットAPI (open, connect, bind, listen, accept, send, recv)
    - [ ] ブロッキングI/O API
    - [ ] ノンブロッキングI/O API
    - [ ] イベント駆動API (select, poll, epoll, kqueue相当)
  - [x] タイムアウト処理
    - [x] ユーザータイムアウト
    - [x] 再送タイムアウト
    - [x] TIME WAITタイムアウト
  - [x] コネクション管理
    - [x] パッシブオープン
      - [x] バックログ
      - [ ] SYNバックログ
    - [x] アクティブオープン
    - [x] コネクションクローズ
  - [x] データ送信
    - [x] MTUによるデータ分割
    - [x] 再送処理
    - [x] フロー制御
    - [ ] 輻輳制御
  - [x] データ受信
    - [x] ACK応答
    - [ ] 部分ACK
  - [ ] シーケンスID循環
  - [ ] URGポインタ
  - [ ] 優先度とセキュリティ
- [ ] UDPプロトコル
- [ ] レイヤー間のゼロコピー転送処理

## 使い方

```bash
# TAPデバイスの作成
sudo ip tuntap add dev tap0 mode tap user $USER
sudo ip addr add 192.168.7.1/24 dev tap0
sudo ip link set dev tap0 up

# アプリケーションの実行
./gradlew run --args="tap0 192.168.7.2 24"
```

## ビルド方法

```bash
./gradlew build
```

## 前提条件

- JDK 21以上
- Kotlinのサポート
- LinuxまたはBSD系OS

## ライセンス

MITライセンス

## 参考資料

- RFC 791 - Internet Protocol
- RFC 792 - Internet Control Message Protocol
- RFC 793 - Transmission Control Protocol
- RFC 826 - Ethernet Address Resolution Protocol
- RFC 1122 - Requirements for Internet Hosts
