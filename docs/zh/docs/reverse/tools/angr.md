# angr 

## Introduction

[angr](https://github.com/angr/angr) 是一个使用 Python 编写的跨平台开源二进制**混合**（Concolic，即 concrete + symbolic）执行引擎，为我们提供了一系列实用的二进制分析工具，更多关于 angr 的介绍信息可以看他们的 [官网](https://angr.io) ，关于 angr 提供的 API 则可以查看[文档](https://api.angr.io/)。

在 CTF 逆向题目当中，angr 强大的混合执行引擎可以帮助我们更好地进行自动化分析，从而大幅度节省解题时间。

## 安装

angr 本体可以直接通过 pip 进行安装：

```shell
$ pip3 install angr
```

[angr-management](https://github.com/angr/angr-management) 是图形化的 angr 界面，安好之后直接在终端输入 `angr-management` 即可直接启动：

```shell
$ pip3 install angr-management
```

[angrop](https://github.com/angr/angrop) 也是 angr 开发团队的项目，可以自动收集 ROP gadget 以及构建 ROP chain：

```shell
$ pip3 install angrop
```

## 基本用法

本节主要讲述 angr 的基本用法以及 angr 当中常用的一些 API。

> 注：[angr_ctf](https://github.com/jakespringer/angr_ctf) 是一个非常好的入门级 angr 练手项目，你可以通过该项目熟悉 angr 的基本用法。

### Project

我们若要使用 angr 来分析一个二进制文件，第一步则是创建一个 `angr.Project` 类——我们一切后续操作都将基于这个类实例进行展开，以下是一个例子：

```python
>>> import angr
>>> bin_path = './test' # file to be analyzed
>>> proj = angr.Project(bin_path)
WARNING | 2022-11-23 19:25:30,006 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
```

首先，我们可以通过一个 project 获取对应二进制文件的基本信息：

```python
>>> proj.arch     # architecture of the binary file
<Arch AMD64 (LE)>
>>> hex(proj.entry)    # entry point of the binary file
'0x401060'
>>> proj.filename # name of the binary file
'./test'
```

- `arch` 是一个 `archiinfo.Arch` 类实例，其包含了运行该文件的 CPU 信息等各种数据：

  - `arch.bits` & `arch.bytes` ：CPU 的字长（单位为位/字节）。

  - `arch.name`：架构名，例如  _X86_  。

  - `arch.memory_endness`：端序，大端为 `Endness.BE` ，小端为 `Endness.LE`。

    > 源码里还有一个 “中端序” `Endness.ME` ：）

#### factory - 实用类工厂

`project.factory` 为我们提供了一些实用的类的构造器。

##### block - 基本块

angr 以基本块为单位分析代码，我们可以通过 `project.factory.block(address)` 获取给定地址所在的**基本块**——一个 `Block` 类实例：

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

##### state - 模拟执行状态

angr 使用 `SimState` 类表示一个 _模拟的程序状态_  （simulated program state），我们的各种操作实际上是由一个 state 步进到另一个 state 的过程。

我们使用 `project.factory.entry_state()` 获取一个程序的初始执行状态，使用 `project.factory.blank_state(addr)` 获取一个程序从指定地址开始执行的空白状态：

```python
>>> state = proj.factory.entry_state()
>>> state = proj.factory.blank_state(0xdeadbeef)
```

- `state.regs`：寄存器状态组，其中每个寄存器都为一个  _位向量_  （BitVector），我们可以通过寄存器名称来访问对应的寄存器（例如 `state.regs.esp -= 12` ）。
- `state.mem`：该状态的内存访问接口，我们可以直接通过 `state.mem[addr].type` 完成内存访问（例如 `state.mem[0x1000].long = 4` ，对于读而言还需指定 `.resolved` 或 `.concrete` 表示位向量或是实际值，例如 `state.mem[0x1000].long.concrete`）。
- `state.memory`：另一种形式的内存访问接口：
  - `state.memory.load(addr, size_in_bytes)` ：获取该地址上指定大小的位向量。
  - `state.memory.store(addr, bitvector)` ：将一个位向量存储到指定地址。
- `state.posix`：POSIX 相关的环境接口，例如 `state.posix.dumps(fileno)` 获取对应文件描述符上的流。

除了这些对模拟执行状态的信息获取接口外，还有一些解决方法的对应接口 `state.solver`，我们将在后续章节中进行讲解。

##### simulation\_manager - 模拟执行器

angr 将一个状态的执行方法独立成一个 `SimulationManager` 类，以下两种写法等效：

```python
>>> proj.factory.simgr(state)
<SimulationManager with 1 active>
>>> proj.factory.simulation_manager(state)
<SimulationManager with 1 active>
```

比较重要的两个条件：

- `simgr.step()`：**以基本块为单位**的单步执行。
- `simgr.explore()`：进行路径探索找到满足相应条件的状态。

`simgr.explore()` 的默认参数是 `find`，即**期望条件**，当模拟执行器在路径探索的过程中发现当前状态满足该条件时，该状态会被放到 `simgr.found` 列表中，若无法找到则该列表为空。

期望条件通常可以是执行到某个地址：

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

期望条件也可以是自定义的以 _状态_ 为参数的布尔函数。例如，若是我们想要寻找一条输出指定字符串的路径，可以选择通过判断该字符串是否在输出中的方式，我们可以通过 `state.posix.dumps(文件描述符)` 来获取对应文件描述符上的字符流：

```
>>> def foo(state):
...     return b"Good" in state.posix.dumps(1)
... 
>>> simgr.explore(find=foo)
<SimulationManager with 17 deadended, 1 found>

```

除了 `find` 参数外，我们也可以指定 `avoid` 参数——模拟器运行中应当要**避开**的条件，当一个状态符合这样的条件时，其会被放在 `.avoided` 列表中并不再往后执行。类似地，`avoid` 参数可以是某个地址，也可以是自定义的布尔函数。

此外，我们还可以通过指定 `num_find` 参数来指定需要寻找的符合条件的状态的数量，若未指定则会在 `.found` 列表中存储所有的符合条件的状态。

### Claripy

`Claripy` 是 angr 的**求解引擎**（solver engine），其内部会无缝混合使用几种后端（concrete bitvectors、SAT solvers 等），对于我们而言一般不需要直接与其进行交互，但通常我们会使用其提供的一些接口

#### bitvector - 位向量

**位向量**（bitvector）是 angr 求解引擎中的一个重要部分，其表示了 **一组位** （a sequence of bits）。

我们可以通过 `claripy.BVV(int_value, size_in_bits)` 或 `claripy.BVV(string_value)` 创建带有具体值（concrete value）的指定长度的位向量值（bitvector value）：

```python
>>> bvv = claripy.BVV(b'arttnba3')
>>> bvv
<BV64 0x617274746e626133>
>>> bvv2 = claripy.BVV(0xdeadbeef, 32)
>>> bvv2
<BV32 0xdeadbeef>
```

相同长度的位向量可以进行运算，对于不同长度的位向量则可以通过 `.zero_extend(extended_bits)` 完成位扩展（0填充）后进行运算，需要注意的是位向量的值运算同样存在溢出：

```python
>>> bvv2 = bvv2.zero_extend(32)
>>> bvv + bvv2
<BV64 0x617274754d102022>
>>> bvv * bvv
<BV64 0x9842ff8e63f3b029>
```

位向量除了代表具体值（concrete value）的 `bitvector value` 以外，还有代表**符号变量**（symbolic variable）的 `bitvector symbol`，我们可以通过 `claripy.BVS(name, size_in_bits)` 创建带名字的指定长度的位向量符号（bitvector symbol）：

```python
>>> bvs = claripy.BVS("x", 64)
>>> bvs
<BV64 x_0_64>
>>> bvs2 = claripy.BVS("y", 64)
>>> bvs2
<BV64 y_1_64>
```

位向量符号与位向量值之间同意可以进行运算，组合成更加复杂的表达式：

```python
>>> bvs3 = (bvs * bvs2 + bvv) / bvs
>>> bvs3
<BV64 (x_0_64 * y_1_64 + 0x617274746e626133) / x_0_64>
```

我们可以通过 `.op` 与 `.args` 获得位向量的运算类型与参数：

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

#### state - 模拟执行状态

##### 状态求解

前面讲到 `state.solver` 提供了一些基于状态的求解接口，例如 solver 同样有创建位向量的 `.BVV()` 与 `.BVS()` 接口。

在需要对位向量符号进行具体值的求解时，我们可以先将位向量符号存放到状态的内存/寄存器中，之后用 simgr 探索到对应的状态后，再使用 `state.solver.eval()` 成员函数来获取对应位向量在当前状态下的值，以下是一个简单的例子：

```python
bvs_to_solve = claripy.BVS('bvs_to_solve', 64)
init_state = proj.factory.entry_state()
init_state.memory.store(0xdeadbeef, bvs_to_solve)
simgr = proj.factory.simgr(init_state)
simgr.explore(find = 0xbeefdead)

solver_state = simgr.found[0]
print(solver_state.solver.eval(bvs_to_solve))
```

##### 内存操作

前面讲到，对于一个状态的内存，我们可以使用 `state.memory` 的对应接口进行操作：

- `state.memory.load(addr, size_in_bytes)` ：获取该地址上指定大小的位向量
- `state.memory.store(addr, bitvector)` ：将一个位向量存储到指定地址

需要注意的是如果要储存具体值，则需要通过 `endness` 参数指定大小端序。

### Emulated Filesystem

在 angr 当中与文件系统间的操作是通过 `SimFile` 对象完成的，SimFile 为对  _存储_  的抽象模型，一个 SimFile 对象可以表示一系列的字节、符号等。

我们可以通过 `angr.SimFile()` 来创建一个模拟文件，创建带有具体值与符号变量的 SimFile 例子如下：

```python
>>> import angr, claripy
>>> sim_file = angr.SimFile('a_file', content = "flag{F4k3_f1@9!}\n")
>>> bvs = claripy.BVS('bvs', 64)
>>> sim_file2 = angr.SimFile('another_file', bvs, size=8) # size in bytes there
```

模拟文件需要与特定的状态进行关联，通过 `state.fs.insert(sim_file)` 或 `sim_file.set_state(state)` 我们可以将 SimFile 插入到一个状态的文件系统中：

```python
>>> state.fs.insert('test_file', sim_file)
```

我们还可以从文件中读取内容：

```python
>>> pos = 0
>>> data, actural_read, pos = sim_file.read(pos, 0x100)
```

对于  _流_  （Streams，例如标准IO、TCP连接等）类型的文件，我们可以用 `angr.SimPackets()` 来创建：

```python
>>> sim_packet = angr.SimPackets('my_packet')
>>> sim_packet
<angr.storage.file.SimPackets object at 0x7f75626a2e80>
```

### Constraints

前面我们讲到位向量之间可以进行运算，类似地，位向量之间也可以进行**比较运算** ，其结果为 `Bool` 类型的对象：

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

对于带有符号值的比较而言， `Bool` 类型的对象直接表示了对应的式子，因此可以作为**约束条件**被添加到一个状态当中，我们可以通过 `state.solver.add()` 为对应状态添加约束：

```python
>>> state.solver.add(bvs == bvv + bvv2)
>>> state.solver.add(bvs2 > bvs * bvv + bvv2)
>>> state.solver.eval(bvs2) # get the concrete value under constraints
```

除了 Bool 类以外，Claripy 还提供了一些以位向量作为结果的运算操作，以下是一个例子（完整的还是去读[文档](https://docs.angr.io/advanced-topics/claripy)吧）：

```python
>>> claripy.If(bvs == bvs2, bvs, bvs2)
<BV32 if bvs_0_32 == bvs2_1_32 then bvs_0_32 else bvs2_1_32>
```

### Function hook

有的时候我们会有需要 hook 掉某个函数的需求，此时我们可以使用 `project.hook(addr = call_insn_addr, hook = my_function, length = n)` 来 hook 掉对应的 call 指令：

- `call_insn_addr`：被 hook 的 call 指令的地址
- `my_function` ：我们的自定义 python 函数
-  `length`： call 指令的长度

我们的自定义函数应当为接收 `state` 作为参数的函数，angr 还提供了 decorator 语法糖，因此以下两种写法都可以：

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

在 angr 中 `angr.SimProcedure` 类用来表示**在一个状态上的一个运行过程**——即函数实际上是一个 SimPrecedure。

我们可以通过创建一个继承自 `angr.SimProcedure` 的类并重写 `run()` 方法的方式来表示一个自定义函数，其中 `run()` 方法的参数为该函数所接收的参数：

```python
class MyProcedure(angr.SimProcedure):
    def run(self, arg1, arg2):
        # do something, this's an example
        return self.state.memory.load(arg1, arg2)
```

自定义函数过程主要用于对文件中的原有函数进行替换，例如 angr 缺省会用内置的一些 SimProcedure 来替换掉一些库函数。

若我们已经有该二进制文件的符号表，我们可以直接使用 `project.hook_symbol(symbol_str, sim_procedure_instance)` 来自动 hook 掉文件中所有的对应符号，其中 `run()` 方法的**参数为被替换函数所接收的参数**，示例如下：

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

当然，在 SimProcedure 的 `run()` 过程中我们也可以使用一些有用的成员函数：

- `ret(expr)`: 函数返回。
- `jump(addr)`: 跳转到指定地址。
- `exit(code)`: 终止程序。
- `call(addr, args, continue_at)`: 调用文件中的函数。
- `inline_call(procedure, *args)`: 内联地调用另一个 SimProcedure。

### stash

在 angr 当中，不同的状态被组织到 simulation manager 的不同的 stash 当中，我们可以按照自己的需求进行步进、过滤、合并、移动等。

#### stash 类型

在 angr 当中一共有以下几种 stash：

- `simgr.active`：活跃的状态列表。在未指定替代的情况下会被模拟器默认执行
- `simgr.deadended`：死亡的状态列表。当一个状态无法再被继续执行时（例如没有有效指令、无效的指令指针、不满足其所有的后继（successors））便会被归入该列表
- `simgr.pruned`：被剪枝的状态列表。在指定了 `LAZY_SOLVES` 时，状态仅在必要时检查可满足性，当一个状态在指定了 `LAZY_SOLVES` 时被发现是不可满足的（unsat），状态层（state hierarchy）将会被遍历以确认在其历史中最初变为不满足的时间，该点及其所有后代都会被  _剪枝_  （pruned）并放入该列表
- `simgr.unconstrained`：不受约束的状态列表。当创建 `SimulationManager` 时指定了 `save_unconstrained=True`，则被认为**不受约束的**（unconstrained，即指令指针被用户数据或其他来源的符号化数据控制）状态会被归入该列表
- `simgr.unsat`：不可满足的状态列表。当创建 `SimulationManager` 时指定了 `save_unsat=True`，则被认为无法被满足的（unsatisfiable，即存在**约束冲突**的状态，例如在同一时刻要求输入既是`"AAAA"` 又是 `"BBBB"`）状态会被归入该列表

还有一种不是 stash 的状态列表——`errored`，若在执行中产生了错误，则状态与其产生的错误会被包裹在一个 `ErrorRecord` 实例中（可通过 `record.state` 与 `record.error` 访问），该 record 会被插入到 `errored` 中，我们可以通过 `record.debug()` 启动一个调试窗口

#### stash 操作

我们可以使用 `stash.move()` 来在 stash 之间转移放置状态，用法如下：

```python
>>> simgr.move(from_stash = 'unconstrained', to_stash = 'active')
```

在转移当中我们还可以通过指定 `filter_func` 参数来进行过滤：

```python
>>> def filter_func(state):
...     return b'arttnba3' in state.posix.dumps(1)
...
>>> simgr.move(from_stash = 'unconstrained', to_stash = 'active', filter_func = filter_func)
```

stash 本质上就是个 list，因此在初始化时我们可以通过字典的方式指定每个 stash 的初始内容：

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

[【ANGR.0x00】从 angr-CTF 入门 angr 的基本用法](https://arttnba3.cn/2022/11/24/ANGR-0X00-ANGR_CTF/)

