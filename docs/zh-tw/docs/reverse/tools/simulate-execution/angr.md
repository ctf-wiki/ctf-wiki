# angr 

## Introduction

[angr](https://github.com/angr/angr) 是一個使用 Python 編寫的跨平臺開源二進制**混合**（Concolic，即 concrete + symbolic）執行引擎，爲我們提供了一系列實用的二進制分析工具，更多關於 angr 的介紹信息可以看他們的 [官網](https://angr.io) ，關於 angr 提供的 API 則可以查看[文檔](https://api.angr.io/)。

在 CTF 逆向題目當中，angr 強大的混合執行引擎可以幫助我們更好地進行自動化分析，從而大幅度節省解題時間。

## 安裝

angr 本體可以直接通過 pip 進行安裝：

```shell
$ pip3 install angr
```

[angr-management](https://github.com/angr/angr-management) 是圖形化的 angr 界面，安好之後直接在終端輸入 `angr-management` 即可直接啓動：

```shell
$ pip3 install angr-management
```

[angrop](https://github.com/angr/angrop) 也是 angr 開發團隊的項目，可以自動收集 ROP gadget 以及構建 ROP chain：

```shell
$ pip3 install angrop
```

## 基本用法

本節主要講述 angr 的基本用法以及 angr 當中常用的一些 API。

> 注：[angr_ctf](https://github.com/jakespringer/angr_ctf) 是一個非常好的入門級 angr 練手項目，你可以通過該項目熟悉 angr 的基本用法。

### Project

我們若要使用 angr 來分析一個二進制文件，第一步則是創建一個 `angr.Project` 類——我們一切後續操作都將基於這個類實例進行展開，以下是一個例子：

```python
>>> import angr
>>> bin_path = './test' # file to be analyzed
>>> proj = angr.Project(bin_path)
WARNING | 2022-11-23 19:25:30,006 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
```

首先，我們可以通過一個 project 獲取對應二進制文件的基本信息：

```python
>>> proj.arch     # architecture of the binary file
<Arch AMD64 (LE)>
>>> hex(proj.entry)    # entry point of the binary file
'0x401060'
>>> proj.filename # name of the binary file
'./test'
```

- `arch` 是一個 `archiinfo.Arch` 類實例，其包含了運行該文件的 CPU 信息等各種數據：

  - `arch.bits` & `arch.bytes` ：CPU 的字長（單位爲位/字節）。

  - `arch.name`：架構名，例如  _X86_  。

  - `arch.memory_endness`：端序，大端爲 `Endness.BE` ，小端爲 `Endness.LE`。

    > 源碼裏還有一個 “中端序” `Endness.ME` ：）

#### factory - 實用類工廠

`project.factory` 爲我們提供了一些實用的類的構造器。

##### block - 基本塊

angr 以基本塊爲單位分析代碼，我們可以通過 `project.factory.block(address)` 獲取給定地址所在的**基本塊**——一個 `Block` 類實例：

```python
>>> block = proj.factory.block(proj.entry) # extract the basic block
>>> block.pp() # pretty-print of disassemble code of the block
        _start:
401060  endbr64
401064  xor     ebp, ebp
401066  mov     r9, rdx
401069  pop     rsi
40106a  mov     rdx, rsp
40106d  and     rsp, 0xfffffffffffffff0
401071  push    rax
401072  push    rsp
401073  lea     r8, [__libc_csu_fini]
40107a  lea     rcx, [__libc_csu_init]
401081  lea     rdi, [main]
401088  call    qword ptr [0x403fe0]
>>> block.instructions # instructions in the block
12
>>> block.instruction_addrs # addr of each instruction
(4198496, 4198500, 4198502, 4198505, 4198506, 4198509, 4198513, 4198514, 4198515, 4198522, 4198529, 4198536)
```

##### state - 模擬執行狀態

angr 使用 `SimState` 類表示一個 _模擬的程序狀態_  （simulated program state），我們的各種操作實際上是由一個 state 步進到另一個 state 的過程。

我們使用 `project.factory.entry_state()` 獲取一個程序的初始執行狀態，使用 `project.factory.blank_state(addr)` 獲取一個程序從指定地址開始執行的空白狀態：

```python
>>> state = proj.factory.entry_state()
>>> state = proj.factory.blank_state(0xdeadbeef)
```

- `state.regs`：寄存器狀態組，其中每個寄存器都爲一個  _位向量_  （BitVector），我們可以通過寄存器名稱來訪問對應的寄存器（例如 `state.regs.esp -= 12` ）。
- `state.mem`：該狀態的內存訪問接口，我們可以直接通過 `state.mem[addr].type` 完成內存訪問（例如 `state.mem[0x1000].long = 4` ，對於讀而言還需指定 `.resolved` 或 `.concrete` 表示位向量或是實際值，例如 `state.mem[0x1000].long.concrete`）。
- `state.memory`：另一種形式的內存訪問接口：
  - `state.memory.load(addr, size_in_bytes)` ：獲取該地址上指定大小的位向量。
  - `state.memory.store(addr, bitvector)` ：將一個位向量存儲到指定地址。
- `state.posix`：POSIX 相關的環境接口，例如 `state.posix.dumps(fileno)` 獲取對應文件描述符上的流。

除了這些對模擬執行狀態的信息獲取接口外，還有一些解決方法的對應接口 `state.solver`，我們將在後續章節中進行講解。

##### simulation\_manager - 模擬執行器

angr 將一個狀態的執行方法獨立成一個 `SimulationManager` 類，以下兩種寫法等效：

```python
>>> proj.factory.simgr(state)
<SimulationManager with 1 active>
>>> proj.factory.simulation_manager(state)
<SimulationManager with 1 active>
```

比較重要的兩個條件：

- `simgr.step()`：**以基本塊爲單位**的單步執行。
- `simgr.explore()`：進行路徑探索找到滿足相應條件的狀態。

`simgr.explore()` 的默認參數是 `find`，即**期望條件**，當模擬執行器在路徑探索的過程中發現當前狀態滿足該條件時，該狀態會被放到 `simgr.found` 列表中，若無法找到則該列表爲空。

期望條件通常可以是執行到某個地址：

```python
>>> simgr.explore(find=0x80492F0) # explore to a specific address
WARNING  | 2023-07-17 04:04:28,825 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing memory with an unspecified value. This could indicate unwanted behavior.
WARNING  | 2023-07-17 04:04:28,825 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING  | 2023-07-17 04:04:28,826 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state
WARNING  | 2023-07-17 04:04:28,826 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING  | 2023-07-17 04:04:28,826 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.
WARNING  | 2023-07-17 04:04:28,826 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7ffeff60 with 4 unconstrained bytes referenced from 0x819af30 (strcmp+0x0 in libc.so.6 (0x9af30))
WARNING  | 2023-07-17 04:04:28,826 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7ffeff70 with 12 unconstrained bytes referenced from 0x819af30 (strcmp+0x0 in libc.so.6 (0x9af30))
<SimulationManager with 1 active, 16 deadended, 1 found>
```

期望條件也可以是自定義的以 _狀態_ 爲參數的布爾函數。例如，若是我們想要尋找一條輸出指定字符串的路徑，可以選擇通過判斷該字符串是否在輸出中的方式，我們可以通過 `state.posix.dumps(文件描述符)` 來獲取對應文件描述符上的字符流：

```
>>> def foo(state):
...     return b"Good" in state.posix.dumps(1)
... 
>>> simgr.explore(find=foo)
<SimulationManager with 17 deadended, 1 found>

```

除了 `find` 參數外，我們也可以指定 `avoid` 參數——模擬器運行中應當要**避開**的條件，當一個狀態符合這樣的條件時，其會被放在 `.avoided` 列表中並不再往後執行。類似地，`avoid` 參數可以是某個地址，也可以是自定義的布爾函數。

此外，我們還可以通過指定 `num_find` 參數來指定需要尋找的符合條件的狀態的數量，若未指定則會在 `.found` 列表中存儲所有的符合條件的狀態。

### Claripy

`Claripy` 是 angr 的**求解引擎**（solver engine），其內部會無縫混合使用幾種後端（concrete bitvectors、SAT solvers 等），對於我們而言一般不需要直接與其進行交互，但通常我們會使用其提供的一些接口

#### bitvector - 位向量

**位向量**（bitvector）是 angr 求解引擎中的一個重要部分，其表示了 **一組位** （a sequence of bits）。

我們可以通過 `claripy.BVV(int_value, size_in_bits)` 或 `claripy.BVV(string_value)` 創建帶有具體值（concrete value）的指定長度的位向量值（bitvector value）：

```python
>>> bvv = claripy.BVV(b'arttnba3')
>>> bvv
<BV64 0x617274746e626133>
>>> bvv2 = claripy.BVV(0xdeadbeef, 32)
>>> bvv2
<BV32 0xdeadbeef>
```

相同長度的位向量可以進行運算，對於不同長度的位向量則可以通過 `.zero_extend(extended_bits)` 完成位擴展（0填充）後進行運算，需要注意的是位向量的值運算同樣存在溢出：

```python
>>> bvv2 = bvv2.zero_extend(32)
>>> bvv + bvv2
<BV64 0x617274754d102022>
>>> bvv * bvv
<BV64 0x9842ff8e63f3b029>
```

位向量除了代表具體值（concrete value）的 `bitvector value` 以外，還有代表**符號變量**（symbolic variable）的 `bitvector symbol`，我們可以通過 `claripy.BVS(name, size_in_bits)` 創建帶名字的指定長度的位向量符號（bitvector symbol）：

```python
>>> bvs = claripy.BVS("x", 64)
>>> bvs
<BV64 x_0_64>
>>> bvs2 = claripy.BVS("y", 64)
>>> bvs2
<BV64 y_1_64>
```

位向量符號與位向量值之間同意可以進行運算，組合成更加複雜的表達式：

```python
>>> bvs3 = (bvs * bvs2 + bvv) / bvs
>>> bvs3
<BV64 (x_0_64 * y_1_64 + 0x617274746e626133) / x_0_64>
```

我們可以通過 `.op` 與 `.args` 獲得位向量的運算類型與參數：

```python
>>> bvv.op
'BVV'
>>> bvs.op
'BVS'
>>> bvs3.op
'__floordiv__'
>>> bvs3.args
(<BV64 x_0_64 * y_1_64 + 0x617274746e626133>, <BV64 x_0_64>)
>>> bvv.args
(7021802812440994099, 64)
```

#### state - 模擬執行狀態

##### 狀態求解

前面講到 `state.solver` 提供了一些基於狀態的求解接口，例如 solver 同樣有創建位向量的 `.BVV()` 與 `.BVS()` 接口。

在需要對位向量符號進行具體值的求解時，我們可以先將位向量符號存放到狀態的內存/寄存器中，之後用 simgr 探索到對應的狀態後，再使用 `state.solver.eval()` 成員函數來獲取對應位向量在當前狀態下的值，以下是一個簡單的例子：

```python
bvs_to_solve = claripy.BVS('bvs_to_solve', 64)
init_state = proj.factory.entry_state()
init_state.memory.store(0xdeadbeef, bvs_to_solve)
simgr = proj.factory.simgr(init_state)
simgr.explore(find = 0xbeefdead)

solver_state = simgr.found[0]
print(solver_state.solver.eval(bvs_to_solve))
```

##### 內存操作

前面講到，對於一個狀態的內存，我們可以使用 `state.memory` 的對應接口進行操作：

- `state.memory.load(addr, size_in_bytes)` ：獲取該地址上指定大小的位向量
- `state.memory.store(addr, bitvector)` ：將一個位向量存儲到指定地址

需要注意的是如果要儲存具體值，則需要通過 `endness` 參數指定大小端序。

### Emulated Filesystem

在 angr 當中與文件系統間的操作是通過 `SimFile` 對象完成的，SimFile 爲對  _存儲_  的抽象模型，一個 SimFile 對象可以表示一系列的字節、符號等。

我們可以通過 `angr.SimFile()` 來創建一個模擬文件，創建帶有具體值與符號變量的 SimFile 例子如下：

```python
>>> import angr, claripy
>>> sim_file = angr.SimFile('a_file', content = "flag{F4k3_f1@9!}\n")
>>> bvs = claripy.BVS('bvs', 64)
>>> sim_file2 = angr.SimFile('another_file', bvs, size=8) # size in bytes there
```

模擬文件需要與特定的狀態進行關聯，通過 `state.fs.insert(sim_file)` 或 `sim_file.set_state(state)` 我們可以將 SimFile 插入到一個狀態的文件系統中：

```python
>>> state.fs.insert('test_file', sim_file)
```

我們還可以從文件中讀取內容：

```python
>>> pos = 0
>>> data, actural_read, pos = sim_file.read(pos, 0x100)
```

對於  _流_  （Streams，例如標準IO、TCP連接等）類型的文件，我們可以用 `angr.SimPackets()` 來創建：

```python
>>> sim_packet = angr.SimPackets('my_packet')
>>> sim_packet
<angr.storage.file.SimPackets object at 0x7f75626a2e80>
```

### Constraints

前面我們講到位向量之間可以進行運算，類似地，位向量之間也可以進行**比較運算** ，其結果爲 `Bool` 類型的對象：

```python
>>> bvv = claripy.BVV(0xdeadbeef, 32)
>>> bvv2 = claripy.BVV(0xdeadbeef, 32)
>>> bvv == bvv2
<Bool True>
>>> bvs = claripy.BVS('bvs', 32)
>>> bvs == bvv + bvv2
<Bool bvs_0_32 == 0xbd5b7dde>
>>> bvs2 = claripy.BVS('bvs2', 32)
>>> bvs2 > bvs * bvv + bvv2
<Bool bvs2_1_32 > bvs_0_32 * 0xdeadbeef + 0xdeadbeef>
```

對於帶有符號值的比較而言， `Bool` 類型的對象直接表示了對應的式子，因此可以作爲**約束條件**被添加到一個狀態當中，我們可以通過 `state.solver.add()` 爲對應狀態添加約束：

```python
>>> state.solver.add(bvs == bvv + bvv2)
>>> state.solver.add(bvs2 > bvs * bvv + bvv2)
>>> state.solver.eval(bvs2) # get the concrete value under constraints
```

除了 Bool 類以外，Claripy 還提供了一些以位向量作爲結果的運算操作，以下是一個例子（完整的還是去讀[文檔](https://docs.angr.io/advanced-topics/claripy)吧）：

```python
>>> claripy.If(bvs == bvs2, bvs, bvs2)
<BV32 if bvs_0_32 == bvs2_1_32 then bvs_0_32 else bvs2_1_32>
```

### Function hook

有的時候我們會有需要 hook 掉某個函數的需求，此時我們可以使用 `project.hook(addr = call_insn_addr, hook = my_function, length = n)` 來 hook 掉對應的 call 指令：

- `call_insn_addr`：被 hook 的 call 指令的地址
- `my_function` ：我們的自定義 python 函數
-  `length`： call 指令的長度

我們的自定義函數應當爲接收 `state` 作爲參數的函數，angr 還提供了 decorator 語法糖，因此以下兩種寫法都可以：

```python
# method 1
@project.hook(0x1234, length=5)
def my_hook_func(state):
    # do something, this is an example
    state.regs.eax = 0xdeadbeef

# method 2
def my_hook_func2(state):
    # do something, this is an example
    state.regs.eax = 0xdeadbeef
proj.hook(addr = 0x5678, hook = my_hook_func2, length = 5)
```

### Simulated Procedure

在 angr 中 `angr.SimProcedure` 類用來表示**在一個狀態上的一個運行過程**——即函數實際上是一個 SimPrecedure。

我們可以通過創建一個繼承自 `angr.SimProcedure` 的類並重寫 `run()` 方法的方式來表示一個自定義函數，其中 `run()` 方法的參數爲該函數所接收的參數：

```python
class MyProcedure(angr.SimProcedure):
    def run(self, arg1, arg2):
        # do something, this's an example
        return self.state.memory.load(arg1, arg2)
```

自定義函數過程主要用於對文件中的原有函數進行替換，例如 angr 缺省會用內置的一些 SimProcedure 來替換掉一些庫函數。

若我們已經有該二進制文件的符號表，我們可以直接使用 `project.hook_symbol(symbol_str, sim_procedure_instance)` 來自動 hook 掉文件中所有的對應符號，其中 `run()` 方法的**參數爲被替換函數所接收的參數**，示例如下：

```python3
import angr
import claripy

class MyProcedure(angr.SimProcedure):
    def run(self, arg1, arg2):
        # do something, this's an example
        return self.state.memory.load(arg1, arg2)

proj = angr.Project('./test')
proj.hook_symbol('func_to_hook', MyProcedure())
```

當然，在 SimProcedure 的 `run()` 過程中我們也可以使用一些有用的成員函數：

- `ret(expr)`: 函數返回。
- `jump(addr)`: 跳轉到指定地址。
- `exit(code)`: 終止程序。
- `call(addr, args, continue_at)`: 調用文件中的函數。
- `inline_call(procedure, *args)`: 內聯地調用另一個 SimProcedure。

### stash

在 angr 當中，不同的狀態被組織到 simulation manager 的不同的 stash 當中，我們可以按照自己的需求進行步進、過濾、合併、移動等。

#### stash 類型

在 angr 當中一共有以下幾種 stash：

- `simgr.active`：活躍的狀態列表。在未指定替代的情況下會被模擬器默認執行
- `simgr.deadended`：死亡的狀態列表。當一個狀態無法再被繼續執行時（例如沒有有效指令、無效的指令指針、不滿足其所有的後繼（successors））便會被歸入該列表
- `simgr.pruned`：被剪枝的狀態列表。在指定了 `LAZY_SOLVES` 時，狀態僅在必要時檢查可滿足性，當一個狀態在指定了 `LAZY_SOLVES` 時被發現是不可滿足的（unsat），狀態層（state hierarchy）將會被遍歷以確認在其歷史中最初變爲不滿足的時間，該點及其所有後代都會被  _剪枝_  （pruned）並放入該列表
- `simgr.unconstrained`：不受約束的狀態列表。當創建 `SimulationManager` 時指定了 `save_unconstrained=True`，則被認爲**不受約束的**（unconstrained，即指令指針被用戶數據或其他來源的符號化數據控制）狀態會被歸入該列表
- `simgr.unsat`：不可滿足的狀態列表。當創建 `SimulationManager` 時指定了 `save_unsat=True`，則被認爲無法被滿足的（unsatisfiable，即存在**約束衝突**的狀態，例如在同一時刻要求輸入既是`"AAAA"` 又是 `"BBBB"`）狀態會被歸入該列表

還有一種不是 stash 的狀態列表——`errored`，若在執行中產生了錯誤，則狀態與其產生的錯誤會被包裹在一個 `ErrorRecord` 實例中（可通過 `record.state` 與 `record.error` 訪問），該 record 會被插入到 `errored` 中，我們可以通過 `record.debug()` 啓動一個調試窗口

#### stash 操作

我們可以使用 `stash.move()` 來在 stash 之間轉移放置狀態，用法如下：

```python
>>> simgr.move(from_stash = 'unconstrained', to_stash = 'active')
```

在轉移當中我們還可以通過指定 `filter_func` 參數來進行過濾：

```python
>>> def filter_func(state):
...     return b'arttnba3' in state.posix.dumps(1)
...
>>> simgr.move(from_stash = 'unconstrained', to_stash = 'active', filter_func = filter_func)
```

stash 本質上就是個 list，因此在初始化時我們可以通過字典的方式指定每個 stash 的初始內容：

```python
>>> simgr = proj.factory.simgr(init_state,
...     stashes = {
...             'active':[init_state],
...             'found':[],
...     })
```

## REFERENCE

[Github - angr](https://github.com/angr/angr)

[angr documentation](https://api.angr.io/)

[【ANGR.0x00】從 angr-CTF 入門 angr 的基本用法](https://arttnba3.cn/2022/11/24/ANGR-0X00-ANGR_CTF/)

