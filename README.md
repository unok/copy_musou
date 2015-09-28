# コピー無双

インターネット繋がってさえいればテキストなどファイルの内容をコピーできます。

## 使い方

## 設定方法

### サーバー

サーバに index.php を配置して copy_musou.db(sqlite)を作成してください。
index.php の上部のコメント部分に DDL が書かれています。

### クライアント

  copy_to.sh user_name access_key < file_name
  
  copy_from.sh user_name access_key > file_name

## 動作環境

### サーバー

  * PHP 5.6.x
    * PHP-mcrypt

### クライアント

  * curl が動くこと
  * サーバーに接続できること

## ライセンス

Copyright (c) Kazuhiko UNO
以下の条件を満たす限り、自由な複製・配布・修正を無制限に許可する。
  * 上記の著作権表示と本許諾書を、ソフトウェアの複製または重要な部分に記載する
  * 本ソフトウェアは無保証である。自己責任で使用する。