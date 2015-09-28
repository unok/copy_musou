# コピー無双(仮)

サーバにつながればテキストなどのファイルの内容をコピーできます。
サーバにはつながるけれどもマシン同士が接続できない場合に便利です。
数時間で作って、かなり適当な作りなので利用にはご注意ください。

## 使い方

## 設定方法

### サーバー

サーバに index.php を配置して copy_musou.db(sqlite)を作成してください。
index.php の上部のコメント部分に DDL が書かれています。

### クライアント

````
copy_to.sh user_name access_key < file_name
````

````
copy_from.sh user_name access_key > file_name
````

## 動作環境

### サーバー

  * PHP 5.6.x
    * mcrypt
    * PDO Sqlite

### クライアント

  * curl が動くこと
  * サーバーに接続できること

## ライセンス


MIT
