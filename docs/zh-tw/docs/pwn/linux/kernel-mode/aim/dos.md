# DoS

對內核進行 DoS 攻擊比較容易，我們可以通過以下幾種方式來實現。

- 觸發內核中的某個漏洞讓內核崩潰
- 觸發內核中的死鎖
- 觸發大量的內核內存泄漏，即存在大量的內存被申請但是沒有被釋放