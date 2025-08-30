# Process-Herpaderping
Process-Herpaderpingの概念検証

## Process Herpaderpingの流れ
mesbox.exeというファイルが悪意のあるファイルだとする
1. mesbox.exeのコピーを作る（ここではoutput.exeとして出力される）
2. output.exeをイメージセクションとしてマッピングする
3. イメージセクションからプロセスを作成する
4. ディスク上にあるoutput.exeを何かしらの値で上書きする
5. リモートスレッドの作成からの実行
6. ハンドルを閉じる

## 使い方
```
> git clone https://github.com/shadoworca777/Process-Herpaderping.git
> cd Process-Herpaderping
> g++ main.cpp utils.cpp -o test.exe
> test.exe
```

## 資料
- https://github.com/jxy-s/herpaderping
- https://jxy-s.github.io/herpaderping/
- https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html
