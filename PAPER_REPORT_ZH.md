# 研究报告：接受之后：基于 eBPF 校准的残差机器论断图谱

**作者：** Chengao Zhang

**单位：** 独立研究者

**电子邮箱：** emtanling@gmail.com

## 摘要

语言理论安全（language-theoretic security）关注的是：一个边界所识别的语言，是否就是下游机制实际解释的语言。在程序验证器边界，已接受制品可能驱动某些有状态的运行时操作，而这些操作并未由预期的报告关系描述。我们引入一个包含五个节点的论断图谱，将制品接受（A）、同后缀因果状态区分（C）、有界可编程性（P）、已计算报告不可因子分解性（R）以及策略/威胁义务（W）区分开来。未来观测商集（future-observation quotient）与行为因子分解判据，将以已接受制品为索引的因果语言同相对于报告的残差语言（residual language）区分开来。

我们给出如下证明义务：一个受到统一控制、可观测且可重置的门，以及一个在有界电路描述域上固定不变的已接受解释器。在精确调度、可接纳性、串行化与帧保持这些前提下，前缀归纳可推出有界组合性。在一项 Linux eBPF 标定中，一个专用的、预分配的、非 LRU 两项哈希映射实现了 NAND：重置后保留一个哨兵项；输入比特决定是更新已有键还是新键；第二次更新的成功谓词提供输出。一个固定不变且已接受的程序处理规范化的 NAND 有向无环图（DAG），其输入不超过 64 个、门不超过 512 个、活跃导线不超过 578 条。

一次带源码快照的 Linux/aarch64 运行覆盖了具名电路和随机电路、联合边界、串行复用、机制对照以及畸形描述符。一个由作者另行运行的语义审计器重建描述符与电路语义，另有一份自行签发的清单检查证据包的完整性。该案例确立了 A 和 C，并在明确的实现前提下支持 P。它没有确立 Linux 报告不可因子分解性，也没有确立策略层面的怪异机器（weird machine）；这一分离正是本报告的主要结果。

**关键词：** 语言理论安全，识别器（recognizer），残差语言，怪异机器，程序验证，抽象解释（abstract interpretation），eBPF。

---

## 1. 引言

语言理论安全将输入边界视为语言识别边界：下游处理就是解释，而输入提供被解释的程序 [1]–[4]。因此，输入校验（validation）与程序验证（program verification）共同承担一种形如识别器的角色。我们的问题从接受之后开始。验证器接受一个程序制品，但这个已接受程序仍可驱动一种由有状态辅助函数与服务操作构成的语言。若要将这种下游语言称为残差的、可编程的、由形状诱导的或怪异机器，需要满足哪些论断？

制品语言与接受之后的操作语言具有不同的载体。验证器可以识别有界执行、带类型的辅助函数使用与内存访问规约，却不必认证通过每一项已文档化运行时服务实现的完整关系。已接受程序可以选择操作、保留服务状态、观测返回值、重置状态并组合效果。这些事实本身都不蕴含验证器缺陷。它们首先确立的是一种以下游操作为内容、以已接受制品为索引的语言。

本文将证据负担组织为如下论断图谱：

| 节点 | 必需事实 | eBPF 案例的状态 |
|---|---|---|
| A — 接受 | 一个固定制品属于 $L_V$ | 已针对保留的目标文件与环境记录 |
| C — 因果状态区分 | 相同后缀与相同非状态上下文，从不同选定运行时状态暴露出不同观测 | 已针对第二次映射更新确立 |
| P — 有界可编程性 | 在明确的帧条件与环境前提下，已接受代码统一地控制、观测、重置并组合状态 | 源码级构造加经审计的回归证据 |
| R — 相对于报告的残差 | C 中的见证由一个实际的已计算报告单元共同覆盖，且该单元未通过行为因子分解测试 | 尚未针对 Linux 确立 |
| W — 策略/威胁义务 | 行为主体可以驱动可编程行为，产生预期策略所排除的效果 | 离线案例尚未确立 |

节点 C 与 R 不得共用同一个名称。我们将以已接受制品为索引的同后缀语言称为 $L_{\mathrm{causal}}$。只有存在实际的已计算单元碰撞时，一个词才进入相对于报告的残差语言 $L_{\mathrm{res}}^R$。P 与 R 在 C 之后分叉：可编程性不蕴含报告碰撞，报告碰撞也不蕴含可编程性。策略层面的怪异机器要求 P 与 W 同时成立；一个*由契约形状诱导、相对于识别器的*怪异机器，还要求在已文档化语义下 R 成立。该图谱把“怪异机器”从一种修辞标签转化为可检查的义务。

可编程性是一个独立的构造问题。状态区分可能是无效的、不受控制的、一次性的，或无法组合的。因此，我们要求程序可见的读出、一个统一的输入分派器、向规范类的重置，以及一个固定不变的已接受解释器；该解释器必须在独立声明的有界描述符域上满足精确调度与帧保持。由此得到的组合定理是一种证明义务分解，而不是普遍的必然性定理。

我们的标定案例是 Linux eBPF。一个固定制品使用专用的两项哈希映射作为饱和资源。重置后，一个哨兵保持活跃。零比特更新该哨兵；一比特插入一个与输入对应的新键。第二个由输入决定的更新仅在输入为 $(1,1)$ 时失败，从而得到 NAND。普通字节码仍负责验证描述符、选择键、路由导线、控制循环并存储输出。宿主解析器把文本 WMC1 规范化到映射中，而验证器仅接受这个固定的 eBPF 制品。

该案例有意用于诊断。它确立 A 和 C，并在所述实现前提下支持 P，尽管相同函数很容易用普通字节码表示。它还表明，为何不能在没有说明的情况下把 P 提升为 R，也不能把 P 与缺失的 W 义务合并。所保留的验证器日志不是已计算抽象单元的提取器，而离线运行没有提供任何遭违反的部署策略。

本文贡献如下：

1. **论断图谱与带类型的语言。** 我们区分已接受制品、因果运行时词、相对于报告的残差词、有界可编程性以及策略/威胁义务。未来观测商集与因子分解判据使节点 R 可测试，而反模型表明这些分支不会坍缩为一体。

2. **有界组合论证。** E1–E3 与精确定义的 E4-D 解释器义务，将局部门正确性、重置、调度以及全局帧条件隔离开来。前缀归纳证明功能性结果；安全性是另一个可选前提。

3. **eBPF 标定案例。** 一个饱和秩 NAND 基与固定解释器以 $D_{64,512}$ 为目标。所记录的测试套件覆盖具名 DAG 与使用固定种子的随机 DAG、深度边界与联合边界、零门案例、串行复用、机制对照以及畸形描述符。

实证范围限于一个具备特权的离线 Linux/aarch64 环境。该案例不是 Linux 报告不透明性结果、并发部署结果、制品参数化编译器、无界机器、漏洞或策略层面的怪异机器。

---

## 2. 相对于识别器的残差语言

### 2.1 识别、执行与报告

设 $V$ 为程序制品上的识别器，$I$ 为具体状态载体 $\Sigma_I$ 上的具体执行语义，其中包括指令引擎、辅助函数、有状态服务以及相关环境。已接受制品语言为

$$
L_V = \{P \mid V(P)=\mathsf{accept}\}.
$$

对于可选的具体轨迹性质 $\mathsf{Safe}$，当下式成立时，该边界在安全性上是健全的：

$$
\forall P\in L_V.\ \mathsf{Tr}_I(P)\subseteq\mathsf{Safe}.
$$

安全健全性是一项前提，不能从一次成功加载中推断得出。它也不同于抽象变换器的完备性。抽象解释通过抽象映射与具体化映射关联具体集合和抽象元素 [5]，但验证器的已接受语言、它所计算的报告、传递函数的健全性及其完备性属于不同判断。尤其是，单元素集合的最佳抽象未必是分析器在汇合控制前沿实际计算的单元。

当报告属于讨论范围时，令 $\mathsf{Report}_V(P,\ell)$ 表示在前沿 $\ell$ 实际计算的有限抽象单元集合，并为其配备已声明的具体化函数 $\gamma_\ell$。前沿覆盖要求

$$
\mathsf{Reach}_I(P,\ell)
\subseteq
\bigcup_{a^\#\in\mathsf{Report}_V(P,\ell)}\gamma_\ell(a^\#).
$$

只有当一个已计算单元同时包含两个具体状态时，二者才受到共同覆盖。这一点排除了一种常见但无效的捷径：证明两个值具有相似的日志打印文本，并不能确定一个已计算抽象单元、一项具体化或共同覆盖。

### 2.2 因果词

对于 $P\in L_V$ 与前沿 $\ell$，令 $\Sigma_{\mathrm{op}}(P)$ 为程序可控制运行时操作的有限字母表，并令 $W^\ell_{\mathrm{run}}(P)\subseteq\Sigma_{\mathrm{op}}(P)^*$ 为已接受代码能够从 $\ell$ 开始执行的词。若将所有此类词都称为残差，就只是为普通轨迹语义改了一个名字；因此，节点 C 使用同后缀因果测试，暂不主张报告有所遗漏。

在比较前固定观测契约

$$
K_{\mathrm{obs}}=(\rho_{\mathrm{obs}},\mathsf{Obs},\mathsf{Slice},\mathsf{Env}).
$$

投影 $\rho_{\mathrm{obs}}$ 选取候选状态；$\mathsf{Obs}$ 固定完整的可见观测轨迹；$\mathsf{Slice}$ 保守地包含后缀或观测者所读取的每个非选定分量；$\mathsf{Env}$ 为两次执行固定同一个相关资源配置、调度、非确定性以及外部干扰选择。以 $\mathsf{ctx}_w(\sigma)$ 表示除 $\rho_{\mathrm{obs}}(\sigma)$ 之外、由后缀读取的分量。只有当 $\mathsf{ctx}_w$ 相等能够固定后缀与观测者读取的每个非选定值（包括时钟、寄存器和服务状态）时，该契约对于 $w$ 才是健全的；缺少这一非干扰条件时，不主张存在 C 见证。

在有定义时，记 $\llbracket w\rrbracket_I(\sigma)=(\tau,o,\sigma')$，其中 $\tau$ 是具体后缀轨迹，$\mathsf{Obs}$ 从中投影出所声明的可见观测。

**定义 1（因果状态介导词族）。** 当 $P\in L_V$、$w\in W^\ell_{\mathrm{run}}(P)$，且存在 $\sigma_0,\sigma_1\in\mathsf{Reach}_I(P,\ell)$，使得 $\llbracket w\rrbracket_I(\sigma_i)=(\tau_i,o_i,\sigma_i')$ 均有定义、均在同一个 $\mathsf{Env}$ 实例中终止且满足下列条件时，称词 $w$ 在 $(P,\ell)$ 处是因果的：

$$
\begin{aligned}
\mathsf{ctx}_w(\sigma_0)&=\mathsf{ctx}_w(\sigma_1),\\
\rho_{\mathrm{obs}}(\sigma_0)&\ne\rho_{\mathrm{obs}}(\sigma_1),\\
\mathsf{Obs}(\tau_0)&\ne\mathsf{Obs}(\tau_1).
\end{aligned}
$$

定义依赖类型的带标签词族

$$
L_{\mathrm{causal}}(V,I;K_{\mathrm{obs}})
=
\{(P,\ell,w)\mid w\text{ 在 }(P,\ell)\text{ 处是因果的}\}.
$$

制品与前沿标签是该类型的一部分。为制品、前沿与操作符号固定可解码的前缀编码后，该词族可以嵌入一个有限字母表上的普通语言；依赖类型记法则使各载体保持可见。宿主描述符既不是 $L_V$ 的另一个元素，也不会自动成为运行时词。它首先成为配置，已接受解释器据此导出调度，而只有同后缀见证才进入 $L_{\mathrm{causal}}$。

该定义相对于观测者与切片。看到结果之后再从上下文中删除较早的输入，会使测试陷入循环论证。因此，eBPF 案例在比较之前就从源码语义声明其后缀；保留转换后的指令转储供人工检查，而不把它交给自动化切片检查器处理。

### 2.3 行为商集与相对于报告的残差语言

固定一个确定性规约

$$
D=(S_D,A_D,O_D,\delta_D,\lambda_D,s_D)
$$

其中包含状态载体 $S_D$、操作字母表 $A_D$、输出字母表 $O_D$，以及定义域相同的偏函数

$$
\delta_D:S_D\times A_D\rightharpoonup S_D,
\qquad
\lambda_D:S_D\times A_D\rightharpoonup O_D.
$$

当且仅当满足以下条件时，投影 $s_D:\Sigma_I\to S_D$ 对具体语义 $I$ 是**充分的**：对于每个具体状态 $\sigma$ 与规约 $D$ 接纳的操作 $a$，具体的 $a$ 步存在，当且仅当 $\delta_D(s_D(\sigma),a)$ 有定义；只要 $\sigma\xrightarrow{a/o}_I\sigma'$，就有

$$
\lambda_D(s_D(\sigma),a)=o,
\qquad
s_D(\sigma')=\delta_D(s_D(\sigma),a).
$$

这里，$o$ 是完整的已声明单步观测，而 $\mathsf{Obs}$ 是从所得输出词出发的固定投影。因此，单个投影状态不能隐藏不同的有定义性或输出。影响转移的每一种环境选择都由 $D$ 固定，或包含在 $S_D$ 中。

令 $\mathsf{Out}_D(r,w)$ 表示通过迭代 $(\delta_D,\lambda_D)$ 得到的、可能无定义但一旦有定义便完整的输出词，以 $\mathsf{Def}_D(r,w)$ 表示 $\mathsf{Out}_D(r,w)\downarrow$，并取延续全集为 $\mathcal W_D=A_D^*$；不可行词以输出无定义表示。对于 $r,r'\in S_D$，定义

$$
\begin{aligned}
r\sim_D r'
&\quad\Longleftrightarrow\quad
\forall w\in\mathcal W_D.\\
&\quad\Bigl(
[\mathsf{Def}_D(r,w)\iff\mathsf{Def}_D(r',w)]\land\\
&\qquad
[\mathsf{Def}_D(r,w)\Rightarrow
\mathsf{Out}_D(r,w)=\mathsf{Out}_D(r',w)]
\Bigr).
\end{aligned}
$$

由于 $\mathcal W_D=A_D^*$ 在操作左前缀下闭合，$\sim_D$ 是右同余：有定义且匹配的 $a$ 步将导向等价后继状态，因为每个后继延续 $w$ 都会作为 $aw$ 被测试。若 $Q_D=S_D/{\sim_D}$ 有限，具体执行会在商状态上导出一个偏 Mealy 转导器。这是语义商集，而不是验证器抽象。

对于具体集合 $F$，定义共同启用的延续

$$
\mathcal W_D(F)
=
\{w\in\mathcal W_D\mid
\forall\sigma\in F.\ \mathsf{Out}_D(s_D(\sigma),w)\downarrow\}.
$$

**命题 1（上下文纤维上的行为因子分解）。** 固定已接受的 $P$、前沿 $\ell$、规约 $D$ 与观测契约 $K_{\mathrm{obs}}$。令 $F\subseteq\mathsf{Reach}_I(P,\ell)$，并假设对于每个 $w\in\mathcal W_D(F)$，$K_{\mathrm{obs}}$ 都是健全的，且

$$
\forall w\in\mathcal W_D(F).\ \forall\sigma,\sigma'\in F.\quad
\mathsf{ctx}_w(\sigma)=\mathsf{ctx}_w(\sigma').
$$

还假设

$$
\mathcal W_D(F)\subseteq W^\ell_{\mathrm{run}}(P).
$$

定义

$$
\beta_D(\sigma)=[s_D(\sigma)]_D,
\qquad
F_{a^\#}=F\cap\gamma_\ell(a^\#).
$$

当且仅当存在 $\sigma_0,\sigma_1\in F_{a^\#}$ 使 $\beta_D(\sigma_0)\ne\beta_D(\sigma_1)$ 时，一个已计算单元 $a^\#$ 在 $F$ 上具有单元级行为碰撞。

当且仅当

$$
\forall a^\#\in\mathsf{Report}_V(P,\ell).\quad
|\beta_D(F_{a^\#})|\le 1.
$$

时，已计算报告在 $F$ 上不存在单元级行为碰撞。

若非空交集族
$\{F\cap\gamma_\ell(a^\#)\mid a^\#\in\mathsf{Report}_V(P,\ell),\ F\cap\gamma_\ell(a^\#)\ne\varnothing\}$
构成 $F$ 的一个划分，令 $\pi_R:F\to\mathsf{Report}_V(P,\ell)$ 把每个状态映射到其唯一单元。此时，该基数条件等价于存在某个 $h:\pi_R(F)\to Q_D$，使得在 $F$ 上 $\beta_D=h\circ\pi_R$。

*证明。* 一个单元无碰撞，当且仅当它覆盖的所有代表都位于同一个未来观测等价类中。这正是上述基数条件，并且它在每个非空单元上定义了 $h$。在构成划分时，报告标签相等蕴含商等价类相等，当且仅当 $\beta_D$ 通过 $\pi_R$ 因子分解。$\square$

**定义 2（相对于报告的残差语言）。** 固定满足命题 1 假设的 $P,\ell,D,F$ 与 $K_{\mathrm{obs}}$。当满足下列条件时，一个带标签的词 $(P,\ell,a^\#,w)$ 在该元组上是相对于报告的残差词：

$$
\begin{aligned}
&(P,\ell,w)\in L_{\mathrm{causal}}(V,I;K_{\mathrm{obs}}),\qquad
w\in\mathcal W_D(F),\\
&\sigma_0,\sigma_1\in F\cap\gamma_\ell(a^\#)
\text{ 是定义 1 的见证},\\
&a^\#\in\mathsf{Report}_V(P,\ell),\qquad
\beta_D(\sigma_0)\ne\beta_D(\sigma_1).
\end{aligned}
$$

当 $D$ 充分，且上述全部上下文、共同延续与报告覆盖假设均成立时，记为 $\mathsf{Adm}(P,\ell,D,F;K_{\mathrm{obs}})$。$L_{\mathrm{res}}^R(V,I,\mathsf{Report};K_{\mathrm{obs}})$ 是在满足 $\mathsf{Adm}$ 的元组上这些带标签词的并集。由于 $\mathsf{Obs}$ 是对 $\mathsf{Out}_D$ 的投影，在所接纳的 $w$ 下不同的观测蕴含所列出的商等价类不等式；将该不等式显式写出，是为了把定义约束到命题 1。这是一个前沿碰撞，而不是声称完整的全程序报告永远无法恢复最终函数。

实例化定义 2 需要实际已计算单元的提取器、已声明的具体化、覆盖以及一个固定的上下文纤维。保留的 Linux 日志没有提供这些对象，因此 eBPF 案例确立了 $L_{\mathrm{causal}}$，但未确立 $L_{\mathrm{res}}^R$。

### 2.4 形状、缺陷与策略

由缺陷诱导的缝隙所使用的行为违反已声明的识别器或运行时契约。与之相对，由契约形状诱导的报告缝隙使用已文档化语义并维持已声明的安全契约，同时，对于该报告意图认证的某个关系，$L_{\mathrm{res}}^R$ 非空。策略层面的怪异机器还需要行为主体控制，以及被某项预期策略所排除的安全相关行为。因此，普通的有状态 API 可以实现转导器，却不满足后两种分类中的任何一种。

---

## 3. 有界状态介导的电路实现

### 3.1 从一种区分到可复用门

一个因果词可以揭示一种区分，却未必支持重复计算。固定一个确定性的门规约 $D$、一个充分的投影 $s_D$、一个规范重置类 $q_0\in Q_D$（将其等同于 $S_D$ 中相应的子集），以及一个非空的可容许具体状态集 $\mathsf{Adm}_G\subseteq\Sigma_I$。门基 $(P_G,\mathit{reset},G,\mathit{observe},D,\mathsf{Adm}_G)$ 满足：

**E1 — 因果基与观测。** 在一个内部前沿处，两个可达的共同上下文状态属于不同的未来观测类，并且一个共同的已启用后缀见证其属于 $L_{\mathrm{causal}}$。被接受的代码存储由此得到的比特，或基于该比特进行分支。

**E2 — 统一输入控制。** 被接受的 $P_G$ 中有一个统一的分派器 $G$，读取运行时比特 $x\in\{0,1\}^2$ 并选择完整的门词 $u(x)$。对于每个满足 $s_D(\sigma)\in q_0$ 的 $\sigma\in\mathsf{Adm}_G$，由 $D$ 定义的执行均终止，并对函数 $g:\{0,1\}^2\to\{0,1\}$ 产生相同的比特 $g(x)$。实验者并非一个针对每个输入选择不同常量程序的外部预言机。

**E3 — 重置。** 重置词满足 $\mathit{reset}\in A_D^*$。对于每个 $\sigma\in\mathsf{Adm}_G$，它均有定义、保持声明的导线单元不变，并终止于满足 $s_D(\tau)\in q_0$ 的 $\tau\in\mathsf{Adm}_G$。如果 $\mathsf{Adm}_G$ 中的两个重置前状态在这些导线单元及固定上下文上相同，并分别重置到 $\tau_0,\tau_1$，那么对于每个 $x\in\{0,1\}^2$，

$$
\mathsf{Out}_D(s_D(\tau_0),u(x))
=
\mathsf{Out}_D(s_D(\tau_1),u(x)).
$$

没有 E1，隐藏差异就不会产生程序可见的效果。没有 E2，实验者可能自行提供真值表。没有 E3，该通道可能只能使用一次。下面的第四个条件在不把电路语义置于外部预言机中的前提下组合该门。

### 3.2 描述符域

本制品使用有界域 $D_{64,512}$。一个描述符为

$$
d=(m,n,(s_i^0,s_i^1)_{0\le i<n}),
$$

其中 $0\le m\le64$、$0\le n\le512$，并且对于每个门 $i$ 和操作数 $b$，

$$
0\le s_i^b<2+m+i
$$

记 $m(d)=m$、$n(d)=n$。导线 0 是常量零，导线 1 是常量一，主输入占用导线 $2$ 至 $2+m-1$，门 $i$ 写入规范目标 $2+m+i$。因此，存活的规范导线数最大为 $2+64+512=578$，最高有效导线索引为 577。

对于 $x\in\{0,1\}^{m(d)}$ 和门函数 $g$，$\mathsf{Eval}_g(d,x)$ 初始化常量和输入向量，随后按照描述符顺序扩展导线向量：

$$
\nu[2+m+i]=g(\nu[s_i^0],\nu[s_i^1]).
$$

宿主编码 $\mathsf{Enc}_U(d,x)$ 将规范化描述符、输入和控制记录写入映射。文本格式 WMC1 是一种宿主序列化。WMC1 和 $d$ 都不是由 $V$ 接受的 BPF 程序；$\mathsf{Sched}_U(d,x)$ 是被接受的 $P_U$ 读取该编码时诱导出的操作调度。

对于 $c=\mathsf{Enc}_U(d,x)$，令 $\mathsf{PhysRun}_U(c)=(s,k,\mu)$ 包含最终状态码、已完成迭代次数和物理映射状态。定义相对于描述符的规范观测

$$
\mathsf{WireObs}_d(\mu)
=(\mu[0],\ldots,\mu[1+m(d)+n(d)])
$$

以及状态掩蔽接口

$$
\mathsf{Run}_{U,d}(c)=
\begin{cases}
(s,\mathsf{WireObs}_d(\mu)),&s=\mathsf{OK},\\
(s,\bot),&s\ne\mathsf{OK}.
\end{cases}
$$

宿主只能从 $\mathsf{OK}$ 结果中投影所请求的输出导线。这条语义规则并未断言过期的物理单元已被擦除。

**E4-D — 有界数据参数化解释。** 当满足以下条件时，一个固定制品 $P_U$ 即在 $D_{64,512}$ 上履行 E4-D：

1. 对于固定的映射定义和所记录的加载环境，$P_U\in L_V$，且这一点与描述符内容 $d$ 和 $x$ 无关；
2. 每个有效的 $\mathsf{Enc}_U(d,x)$ 都建立一个回调前状态 $\mu^{(0)}$，其中 $\mu^{(0)}[0]=0$、$\mu^{(0)}[1]=1$，且对于 $0\le j<m(d)$ 有 $\mu^{(0)}[2+j]=x_j$；它严格按顺序执行回调位置 $0,\ldots,n(d)-1$，并以 $\mathsf{PhysRun}_U=(\mathsf{OK},n(d),\mu)$ 终止；
3. 一个外部临界区覆盖足迹中每个共享映射的设置、调用和读回；
4. 每次迭代 $i$ 都验证规范形式，并恰好复制其两个较早的源导线；紧接重置之前的完整具体状态 $\sigma_i$ 属于 $\mathsf{Adm}_G$；随后，该次迭代进行重置并调用 E1–E3 门，仅将得到的 $g$ 比特写入目标 $2+m(d)+i$ 和声明的审计单元，并保持描述符及所有较早导线不变；以及
5. 任何执行都不超过 512 次迭代；与此同时，由所声明的描述符校验器覆盖的格式错误核心 ABI 控制或描述符配置以非 $\mathsf{OK}$ 状态终止，完成的迭代次数至多为 512，且语义结果为 $(s,\bot)$。

这些条款是有意设定的证明义务。特别是，E4-D 要求写入门结果，并满足精确的迭代与终止行为；仅仅遍历描述符并不足够。

### 3.3 实现定理

**定理 1（显式义务下的有界组合）。** 假设固定的 $P_U$ 在其声明的确定性且串行化环境下履行 E4-D，并且其嵌入的门基以函数 $g$ 满足 E1–E3。那么，对于每个 $d\in D_{64,512}$ 和 $x\in\{0,1\}^{m(d)}$，

$$
\mathsf{Run}_{U,d}(\mathsf{Enc}_U(d,x))
=(\mathsf{OK},\mathsf{Eval}_g(d,x))
$$

恰好在 $n(d)$ 次迭代后成立。如果识别边界还对 $\mathsf{Safe}$ 满足安全健全性，那么这些轨迹也满足 $\mathsf{Safe}$。

*证明概要。* E4-D 初始化常量/输入前缀。在迭代 $i$ 中，描述符约束保证两个源都是较早的单元。E3 提供 $q_0$，E2 从该类提供 $g$，而 E4-D 仅将其写入规范目标，同时保持已经建立的前缀不变。对前缀进行归纳，可在 $n(d)$ 次迭代后得到 $\mathsf{Eval}_g$；精确调度条款给出终止状态 $\mathsf{OK}$。E1 确立该门使用了一个因果状态区分，但布尔归纳并不需要 E1。安全性仅由单独的健全性前提推出。$\square$

该定理分解了局部门、重置、调度和帧义务；它并未声称测试枚举了整个描述符域。它也没有证明 E4-A；在 E4-A 中，编译器会为每个电路生成不同的、被接受的 BPF 对象。

---

## 4. eBPF 校准案例

### 4.1 执行边界

程序 $P_U=\mathit{wm\_circuit}$ 是一个固定的 eBPF 制品，其节为 $\mathit{SEC}(\text{syscall})$。在所记录的环境中，内核验证器接受该程序，用户空间则通过 $\mathit{bpf\_prog\_test\_run\_opts}()$ 离线执行它；Linux 文档同时说明了用户空间程序执行以及 syscall 节/程序类型映射 [6]、[7]。其中不涉及任何实时钩子。该实验在本地以特权方式运行，其接受与资源事实仍局限于所记录的程序类型、内核和体系结构。

载体边界如下：

| 宿主数据与验证 | 识别单元 | 接受后解释 |
|---|---|---|
| 文本 WMC1 $\rightarrow$ 规范化映射配置 $\mathsf{Enc}_U(d,x)$ | $V$ 接受固定的 $P_U$，而非 WMC1 或 $d$ | $P_U$ 读取映射 $\rightarrow\mathsf{Sched}_U(d,x)\rightarrow$ 辅助函数返回值和导线观测 |

门映射 $G0$ 是一个专用的 $\mathit{BPF\_MAP\_TYPE\_HASH}$ 映射，且 $\mathit{max\_entries}=2$。它不是 LRU 映射，并保留默认预分配；Linux 文档说明了该映射类型的条目上限、默认预分配、更新标志，以及成功/负错误值约定 [8]。该规约要求重置成功，并要求一个外部临界区覆盖足迹中每个映射的设置、调用和读回。串行测试框架满足无交错使用模式，但 eBPF 程序本身没有实现并发锁。

### 4.2 饱和秩 NAND

该门使用两两不同的键：哨兵 $S$、输入键 $A$ 和输入键 $B$。重置操作删除三者并插入 $S$，从而建立占用数一。对于第一个输入，零会更新 $S$，一会插入新的 $A$；对于第二个输入，零会更新 $S$，一会插入新的 $B$。命题 2 给出抽象占用规律。对于 Linux 实例，已有键成功、低于容量时新键成功，以及达到容量时新键失败，均为仅限于有效参数、默认预分配、成功重置、无干扰及所记录 Linux 6.17 环境的显式前提。参考文献 [8] 提供映射接口和返回约定；保留的原始返回值与机制控制在该对象上实例化了这一规律。该门只观测第二次更新的成功谓词，而不观测可移植的错误编号。

四种执行如下：

| $a$ | $b$ | 重置后的操作词 | 第二次操作前的状态 | 第二次结果 | 输出 $[\mathit{ret}=0]$ |
|---:|---:|---|---|---|---:|
| 0 | 0 | $\mathit{updS};\mathit{updS}$ | $\{S\}$ | 成功 | 1 |
| 0 | 1 | $\mathit{updS};\mathit{insB}$ | $\{S\}$ | 成功 | 1 |
| 1 | 0 | $\mathit{insA};\mathit{updS}$ | $\{S,A\}$ | 成功 | 1 |
| 1 | 1 | $\mathit{insA};\mathit{insB}$ | $\{S,A\}$ | 失败 | 0 |

**命题 2（饱和秩 NAND）。** 令秩表示容量为 $k\ge2$ 的资源中已占用名称的数量。重置在已有 $S$ 的情况下建立秩 $k-1$，而两两不同的 $A$ 和 $B$ 是新名称。更新已有名称会成功且不改变秩；当秩低于 $k$ 时，更新新名称会成功并增加秩；当秩达到 $k$ 时，该操作会失败且不改变秩。将零分派给 $S$，将第一个一分派给 $A$，将第二个一分派给 $B$。第二次更新的成功谓词为 $\mathsf{NAND}(a,b)$。

*证明。* 当 $a=0$ 时，第一次更新保持秩 $k-1$，因此无论哪一种第二次更新都会成功。当 $a=1$ 时，第一次更新将秩提高到 $k$；当 $b=0$ 时，由于 $S$ 已存在，第二次更新成功；当 $b=1$ 时，由于 $B$ 是新名称，第二次更新失败。因此，输出依次为 $1,1,1,0$。$\square$

对于定义 1 的具体见证，取 $P=\mathit{wm\_circuit}$，并令 $\ell$ 为 $\mathit{circuit\_step\_cb}$ 中第一次由输入决定的操作之后、第二次映射更新之前的点。取 $w=\mathit{insB}$，并令 $\rho_{\mathrm{obs}}(\sigma)=K_{G0}(\sigma)$，即 $G0$ 的已占用键集合。输入 $(0,1)$ 和 $(1,1)$ 在 $\ell$ 处分别到达状态 $\sigma_0$ 和 $\sigma_1$，其中 $K_{G0}(\sigma_0)=\{S\}$、$K_{G0}(\sigma_1)=\{S,A\}$。对于后缀更新返回值，定义 $\mathsf{Obs}(\tau)=[\mathit{ret}(\tau)=0]$。切片和 $\mathsf{ctx}_w$ 包括共同的程序点、键 $B$、值、$G0$ 标识和静态属性（映射类型、容量和预分配）、更新标志、相关的控制与导线值，以及串行化执行环境，但不包括所选择的动态内容 $K_{G0}$。契约中的 $\mathsf{Env}$ 固定内核、对象、映射实例、调度和无干扰条件。两个 $\mathit{insB}$ 后缀均终止，观测值分别为 1 和 0。较早的输入 $a$ 不会被后缀读取，而它唯一留存且与后缀相关的效果就是所选择的键集合。因此，上下文相同、所选状态不同，且 $\mathit{insB}$ 见证 $(P,\ell,w)\in L_{\mathrm{causal}}(V,I;K_{\mathrm{obs}})$。

在该门规约下，取 $s_{D_G}(\sigma)=(\mathit{phase}(\sigma),K(\sigma))$，其中 phase 取值于重置/哨兵/第一次操作/第二次操作阶段，而 $K\subseteq\{S,A,B\}$ 且 $|K|\le2$。该载体以及由此得到的未来观测商集是有限的。完整的重置加门操作词未必是因果的，因为重置会消除传入差异；该见证由第一次操作之后的内部前沿标记。

该机制并未为 eBPF 增加外延意义上的布尔表达能力。它是一个校准案例，表明有文档记录的有状态服务可以提供一个可复用的接受后阶段逻辑门；它本身并不能确立报告遗漏。

### 4.3 固定解释器与映射 ABI

除 $G0$ 外，$\mathit{wm\_circuit}$ 还使用 $\mathit{TAPE}$ 和四个解释器映射：

- $\mathit{TAPE}$ 记录构建变体、容量、选定的原始返回值和错误计数；
- $\mathit{CIRCUIT}$ 存储规范化记录 $(\mathit{op},\mathit{src0},\mathit{src1},\mathit{dst})$；
- $\mathit{WIRES}$ 存储常量、主输入和规范的 SSA 风格门输出；
- $\mathit{VM\_CONTROL}$ 提供 ABI 版本和声明的计数；
- $\mathit{VM\_TRACE}$ 存储每个门的有效性与输出，并且对于状态介导变体，还存储第二个辅助函数的原始返回值。

宿主解析器检查并规范化 WMC1、写入映射单元，并保留所请求的输出列表。只有在 $\mathit{status}=\mathsf{OK}$ 后才会投影该列表，且 BPF 从不读取该列表。源代码层面的掩蔽由宿主控制流保护；负向测试套件测试拒绝状态和执行计数，而非注入的运行时掩蔽路径。在内核内部，一个有界循环处理至多 512 个描述符。每次迭代在调用辅助函数之前复制描述符和源值，重置 $G0$，调用该门，并按键更新规范目标，从而避免在这些调用之间保留映射值指针。

规范目标防止源/目标别名和前向引用。所覆盖的格式错误版本、计数、操作码、目标或源会得到非 $\mathsf{OK}$ 状态。对于有效描述符，拓扑限制保证每个源都位于更早位置。外部的全事务串行化防止并发混合配置；连续的串行调用会覆盖共享单元，而过期的物理单元可能仍然保留。

验证器的接受单元是固定的解释器制品，而非每个描述符，尽管测试框架可能针对不同数据集重新加载同一个对象。改变映射配置会改变被解释的电路。这是 E4-D 的载体区分，而不是编译器为每个电路生成新的被接受 BPF 对象的证据。

### 4.4 源代码层面的不变式与证据边界

**引理 1（源代码层面的解释器前缀不变式）。** 假设有文档记录的辅助函数语义、E4-D 串行化环境、有效的 $\mathsf{Enc}_U(d,x)$，并且所捕获的转换后对象保留了经人工检查的源代码控制/数据依赖。对于每个满足 $0\le t\le n(d)$ 的整数 $t$，在 $t$ 次成功回调之后，索引低于 $2+m(d)+t$ 的规范导线所构成的序列等于 $\mathsf{Eval}_{\mathsf{NAND}}(d,x)$ 的对应前缀。

*证明概要。* 外层程序初始化常量，并保留宿主写入的输入。回调验证当前操作码、目标和较早的源，随后复制描述符和源比特。命题 2 给出重置后的 NAND；成功时仅写入规范目标，并增加完成计数。外层循环恰好请求 $n(d)$ 次回调，并同时检查循环返回值和完成计数。对 $t$ 进行归纳即可得到前缀结论。这是由保留的转换后转储支持人工检查的源代码层面论证，而非经过机器检查的 eBPF 语义证明。$\square$

E4-D 实现论证与制品的对应关系如下：

| 条款 | 源代码/捕获证据 | 实证检查或剩余前提 |
|---|---|---|
| 1 — 固定接受单元 | 保留的正常对象、验证器元数据、捕获的已加载程序标签 | 描述符变化不会产生新的 BPF 制品 |
| 2 — 初始状态与精确调度 | $\mathit{wm\_circuit}$ 初始化常量、调用 $\mathit{bpf\_loop}$，并检查循环返回值/完成计数 | 命名、随机、零、深度和联合边界运行 |
| 3 — 串行化 | 运行器串行调用各项配置；程序不含锁 | 覆盖整个映射集合的临界区仍是外部前提 |
| 4 — 门/帧条件 | $\mathit{circuit\_step\_cb}$ 验证/复制源、重置 $G0$，并更新一个规范目标 | 语义审计器检查所发出的目标与输出 |
| 5 — 边界/错误 | 计数防护、回调失败状态、宿主侧状态掩蔽防护 | 八个负向案例检查状态/计数；掩蔽路径仅由源代码防护 |

因此，A 和 C 已被记录，而 P 在所述源到对象及串行化前提下得到支持。节点 R 和 W 缺失：未提供 Linux 报告单元提取器或部署策略。

---

## 5. 评估


### 5.1 记录的环境与主要运行

主要证据是与报告绑定且包含源代码快照的运行
$\mathit{results/interpreter/interpreter\text{-}final\text{-}20260711\text{-}02/}$。它记录了 Ubuntu 24.04、aarch64 上的 Linux 6.17.0-35-generic，并保存了四个 BPF 变体、所捕获的已加载程序元数据、验证器日志、描述符、JSONL 输出、由作者执行的语义审计、包括本报告在内的选定源代码，以及一份自行签发的 SHA-256 清单。这是一次由作者生成的运行，并带有一项单独由作者执行的审计，而非第三方复现。

该数据集恰好包含

$$
38{,}533
=26{,}488\ \text{条逐门记录}
+12{,}037\ \text{条成功运行记录}
+8\ \text{条负对照记录}.
$$

这些是异构的证据行，而不是“38,533 个测试”。特别是，显式算术基线的门记录不包含由状态介导的辅助函数返回值轨迹。

### 5.2 覆盖范围

| 数据集 | 输入覆盖 | 成功运行次数 | 逐门记录数 | 目的 |
|---|---:|---:|---:|---|
| 9 个具名电路 | 对每个电路穷举 | 39 | 166 | 典型组合函数，包括 NAND、多路复用器和加法器 |
| 100 个随机 DAG | 对每个 DAG 穷举；至多 6 个输入和 24 个门；种子 3235823838 | 1,876 | 23,776 | 固定种子的结构与语义回归测试 |
| 深度边界 | 对一条 512 门链的单个输入取两种赋值 | 2 | 1,024 | 门数量与深度边界 |
| 联合边界 | 全零向量和全一向量 | 2 | 1,024 | 64 个输入、512 个门、578 条导线，包括导线 577 |
| 零门边界 | 对 0 输入/0 门常量描述符的专门重复测试 | 1 | 0 | 空电路执行 |
| 串行交替 | NAND/全加器/多路复用器交替 | 10,000 | 0 | 重置与跨调用污染回归测试 |
| 容量 64 对照 | 具名电路的输入 | 39 | 166 | 消除容量饱和 |
| 强制哨兵对照 | 具名电路的输入 | 39 | 166 | 消除第二次新键插入 |
| 显式基线 | 具名电路的输入 | 39 | 166 | 普通算术 NAND 的接受性与语义 |
| 畸形核心 | 8 个 ABI/计数/操作/目标/引用案例 | — | — | 预期得到非 $\mathsf{OK}$ 状态与执行计数 |

每个具名电路和随机电路都穷举其自身的有限输入域。64 输入联合边界必然使用两个选定向量，而不是全部 $2^{64}$ 个输入。因此，该语料库是针对实现的回归证据，也是对证明前提的检查；它既不是对所有 $D_{64,512}$ 描述符的枚举，也不是实证证明。

串行交替数据集复用同一个已加载的测试框架，连续调用 10,000 次。它可检测串行使用下常见的重置或陈旧状态回归。它不是并发压力测试，因而无法确立全局临界区前提；该前提仍位于 eBPF 程序之外。

### 5.3 单独的语义审计与完整性检查

由作者执行的语义审计器不信任运行器的通过标志。其另一套实现：

1. 重构每一个具名源描述符以及两个生成的边界描述符；
2. 根据固定种子逐字节重新生成 100-DAG 语料库；
3. 解码 WMC1，重新计算预期的完整线向量，并比较每个发出的门目标值和投影输出；
4. 检查每条边界门记录以及全部八个畸形核心案例；
5. 将每个 JSONL 运行时标签与所捕获的已加载程序元数据进行交叉核对。

语义审计报告成功。完成该审计后，运行脚本写入并验证一份自行签发的 SHA-256 清单，作为单独的完整性检查；其验证器同样报告成功。该清单能检测证据包的意外偏离，但不构成强来源证明、签名、时间戳、认证或独立复现。所捕获的标签是一项防混淆检查，而源代码快照仅覆盖测试框架选定的文件。

### 5.4 机制归因

三个变体将容量机制与真值表及制品接受性区分开来。

第一，将容量从 2 增加到 64，可消除被测调度中的饱和；具名语料库对照中的全部 166 个门输出均变为 1。第二，强制第二个一位输入更新 $S$，可消除新 $B$ 的插入；全部 166 个输出同样变为 1。第三，一个算术基线在不使用容量机制的情况下计算 NAND，并产生预期的具名电路结果。全部四个变体——状态介导的门、两个对照以及基线——都能在记录的环境中加载并执行。

这些对照支持机制归因：饱和和第二个新名称对于门输出零都是必要的。它们并未显示等价的验证器报告。基线确认，该机制没有获得普通字节码无法实现的新布尔函数。

### 5.5 校准结果

Linux 的验证器文档将其目标表述为判定程序安全性并验证路径、参数和内存访问 [9]；它并未规定对由映射介导的计算给出完备的功能证书。因此，将辅助函数返回值保留为未知，可能与该文档所述目标一致。本案例是一项校准，而非不健全接受的证据：它确立节点 C，并在其实现前提下支持节点 P，而报告提取器的缺失阻断了节点 R。

### 5.6 有效性威胁

实验使用了一个内核构建版本和一种体系结构。论证依赖于一个专用的预分配非 LRU 映射、成功重置、互异的键、所述更新律，以及整个映射集合上的互斥。会发出门记录的数据集保留原始返回值；10,000 次运行的压力测试文件记录运行/状态/输出证据，但不包含逐门原始行。证明只使用成功与失败之分，并不承诺可移植的错误码。

有限测试不能证明所有 $D_{64,512}$。相反，定理 1 依赖于所陈述的源代码级初始化、验证、有序迭代、门和帧义务；语料库旨在寻找反例。转换后的转储和验证器日志被保留下来以供人工检查及清单哈希使用，而未被自动化数据流检查器消费。状态掩蔽具有源代码顺序保护，而负面测试套件测试的是拒绝/状态，并非注入的掩蔽路径。不存在机器检查的 eBPF 语义证明，且只有在可选的 $\mathsf{Safe}$ 结论中才假定生产验证器的安全健全性。

---

## 6. 相关工作

语言理论安全提供了识别/解释框架 [1]–[4]。Palmer、Rogers 和 Adams 将低级接口重构为由缓冲区、调用、标志、引用和状态依赖操作组成的语言 [10]。Bratus 等人与构造性示例将非预期计算刻画为可编程机器 [11]–[13]；Dullien 研究可利用性 [14]，Paykin 等人则明确了源/目标策略边界 [15]。Vanegue 关于携带证明代码的工作是抽象侧一个密切相关的先例：证明模型之外的计算可以充当影子执行 [16]。

| 工作方向 | 主要对象 | 本文新增的区分 |
|---|---|---|
| 语言理论安全 [1]–[4] | 被识别的输入语言与下游解释器 | 被接受的制品与其接受后的操作词 |
| 以对象为中心的追踪 [10] | 有效的低级操作流 | 被接受制品/前沿标签，以及预先声明的同后缀因果测试 |
| 携带证明代码的怪异机器 [16] | 证明抽象之外的计算 | 实际已计算单元的因子分解与仅由状态介导的可编程性 |
| 不安全编译 [15] | 源/目标上下文策略 | 相对于报告的节点 R 与策略/威胁节点 W 分离 |

抽象解释提供了具体状态、已计算单元、健全性和完备性的术语 [5], [17]。我们的判据关注实际已计算单元的因子分解；它并不把报告不确定性等同于标准抽象解释中的不完备性。PREVAIL 是一个独立的 eBPF 分析器，具有自身的健全性论证 [18]；而三态数工作证明的是域级性质 [19]，并非该内核上生产验证器的端到端健全性。MOAT 在接受之后隔离 BPF [20]，通过限制接受后语义的影响来补充我们的边界分析。Anantharaman 等人将怪异指令定位于不同解释之间的 mismorphism（失配态射）中 [21]；本文的节点 R 要求一个更窄的见证，即不同的未来观测类占据同一个实际的已计算报告单元。

---

## 7. 局限、启示与展望

### 7.1 论断图谱具有严格区分

为将全部五个节点置于同一载体上，固定模型
$M=(V,I,\mathsf{Report},K_{\mathrm{obs}},P_*,\ell_*,D_R,F_R,\mathcal A,\mathcal E,\mathsf{Drive},\mathsf{Pol})$，
其中 $\mathcal A$ 和 $\mathcal E$ 分别是行为主体集合与效果集合，$\mathsf{Drive}\subseteq\mathcal A\times\mathcal E$ 记录行为主体可以通过指定的 $P_*$ 驱动的效果，$\mathsf{Pol}\subseteq\mathcal E$ 是允许效果的集合。定义：当 $P_*\in L_V$ 时 $A(M)$ 成立；当 $\exists w.\,(P_*,\ell_*,w)\in L_{\mathrm{causal}}(V,I;K_{\mathrm{obs}})$ 时 $C(M)$ 成立；当 $P_*$ 是一个固定且被接受的有界解释器，且存在一个嵌入门基 $(P_G,\mathit{reset},G,\mathit{observe},D_G,\mathsf{Adm}_G)$ 和一个非常量函数 $g$，该门基关于 $g$ 满足 E1–E3，并且 $P_*$ 使用该门基履行 E4-D 时，$P(M)$ 成立；当 $\mathsf{Adm}(P_*,\ell_*,D_R,F_R;K_{\mathrm{obs}})$ 成立，且某个 $(P_*,\ell_*,a^\#,w)$ 恰好在该元组上构成相对于报告的残差时，$R(M)$ 成立；当 $\exists a\in\mathcal A,\exists e\in\mathcal E.\,(a,e)\in\mathsf{Drive}\land e\notin\mathsf{Pol}$ 时，$W(M)$ 成立。

**命题 3（论断节点之间的非蕴含关系）。** 在此模型类上，下列蕴含均不成立：

$$
A\not\Rightarrow C,\quad
C\not\Rightarrow P,\quad
C\not\Rightarrow R,\quad
P\not\Rightarrow R,\quad
R\not\Rightarrow P,\quad
P\not\Rightarrow W,\quad
R\not\Rightarrow W.
$$

此外，策略层面的怪异机器不一定满足 R；只有由形状诱导且相对于识别器的子类要求 $P\land R\land W$。

*由有限反模型给出的证明。* 对于 $A\not\Rightarrow C$，仅接受 $\mathit{skip}$ 并拒绝另一个安全的常量程序；该被接受系统不存在因果操作。对于 $C\not\Rightarrow P$ 和 $R\not\Rightarrow P$，使用状态 $\{0,1,\bot\}$、一次输出该位并转移至汇点 $\bot$ 的读取操作、不设重置，并使用一个同时覆盖 0 和 1 的报告单元。对于 $C\not\Rightarrow R$，使用一个可重置的双状态转导器，其报告对每个未来观测类各有一个单元。对于 $P\not\Rightarrow R$，使用任意满足 E1–E3 和 E4-D 的、被接受的有界 NAND 解释器，并采用相同的精确报告划分。对于 $P\not\Rightarrow W$，令 $\mathsf{Pol}=\mathcal E$；采用具有同样宽松策略的单报告单元破坏性读取模型，也可得到 $R\not\Rightarrow W$。最后，选择一个满足 P 的模型，将一个由行为主体驱动的效果置于 $\mathsf{Pol}$ 之外，并令报告区分所有相关的未来观测类；于是 $P\land W\land\neg R$。因此，策略层面的怪异机器地位通常不要求 R。$\square$

定理 1 仅处理在给定显式重置与组合前提后从 C 到 P 的构造。仅凭标准抽象解释的不完备性或接受不完备性，并不蕴含任何后续节点。

### 7.2 防御启示

该模型提出一种三部分审计。分别声明被识别的属性和报告；枚举已接受代码可以驱动的有状态操作语言，包括环境假设；随后测试与安全相关的商类是否可通过所选报告进行因子分解。违反契约需要修复实现。符合文档的行为若违反预期的报告关系，则需要细化报告、限制运行时或进行隔离。如果报告从未承诺该关系，且策略允许该行为，那么可能不存在验证器缺陷。

### 7.3 怪异机器地位与未来的形状定理

在源到对象对应关系与串行化前提下，eBPF 案例支持节点 P：被接受的代码控制、重置并组合一个有状态 NAND 基底。它并未确立 R 或 W。如果符合文档的因果行为还不满足一项已声明的报告因子分解契约，则这个额外缝隙是由契约形状诱导的；当前 Linux 制品并未确立此前提。怪异机器的安全地位还要求存在行为主体以及被策略排除的效果，而离线运行中不存在这两者。

未来的形状定理必须推导而非假定两个闭包性质。**宏闭包**必须在预算内重命名并组合局部操作时保持接受性。**报告嵌入**必须在组合之后保留实际已计算单元中的相关碰撞。上下文敏感分析可以使任一性质失效，且预算不一定具有可加组合性。以声明的观测语义实例化的完备壳理论 [17]，或许可以刻画所需的报告细化，但它不会凭空产生可达性、控制、重置、路由或策略违反。

### 7.4 其余局限

证据是在一个 Linux/aarch64 设置上的一个有界组合电路解释器。它不是第二套系统的结果、并发结果、E4-A 编译器结果或无界结果。由于不存在 Linux 报告提取器，报告框架与校准案例在节点 R 处仍然断开。最终证据包由作者生成，并带有一项单独由作者执行的语义审计；它不是第三方复现。

---

## 8. 结论

程序验证是一道语言理论安全边界，但制品接受与接受后解释使用不同的语言。我们将以已接受制品为索引的因果族 $L_{\mathrm{causal}}$ 与相对于报告的 $L_{\mathrm{res}}^R$ 分离，给出了行为因子分解判据，并分解了有界状态介导组合的各项义务。

eBPF 校准确立了 A 和 C，并在显式的源到对象、环境和帧条件前提下支持 P。一个双条目映射的饱和更新代数实现了 NAND，而一个固定制品可处理至多具有 64 个输入、512 个门和 578 条导线的电路。它并未确立 Linux 报告的不可因子分解性，也未确立策略/威胁义务。论断图谱将这条边界转化为结果而非歧义：接受后可编程性是可测量的，但它尚不是由形状诱导且相对于识别器的怪异机器。

---

## 伦理与数据可用性

所有实验均在隔离的本地虚拟机中运行，不将任何程序附加到实际运行中的网络或内核钩子，不以任何第三方为目标，也不尝试内存破坏、验证器绕过或权限提升。该制品仅使用合法的辅助函数调用和有界执行。

配套仓库位于 https://github.com/Emtanling/eBPF-machine。与报告绑定的源代码和证据位于 `results/interpreter/interpreter-final-20260711-02/`；该目录包含保存的 BPF 变体、环境记录、验证器日志、转换后的反汇编、WMC1 描述符、JSONL 数据集、单独由作者运行的审计代码以及一份完整性清单。该清单为自行签发，仅用于防止证据包意外漂移。

## 致谢与 AI 使用声明

OpenAI Codex 在整篇手稿中被用于协助结构组织、起草、修订和语言编辑，并在配套制品中用于协助代码与测试修订、文档同步以及执行由作者指导的检查。作者独立审查并验证了所有主张、证明、引用、源代码更改和实验结果，并对本工作承担全部责任。作者声明不存在利益冲突。

## 作者贡献

Chengao Zhang：概念化、方法论、软件、验证、调查、写作（初稿），以及写作（审阅与编辑）。

---

## 参考文献

[1] L. Sassaman, M. L. Patterson, S. Bratus, and M. E. Locasto, “Security Applications of Formal Language Theory,” *IEEE Systems Journal*, vol. 7, no. 3, pp. 489–500, 2013, doi: 10.1109/JSYST.2012.2222000.

[2] F. Momot, S. Bratus, S. M. Hallberg, and M. L. Patterson, “The Seven Turrets of Babel: A Taxonomy of LangSec Errors and How to Expunge Them,” in *2016 IEEE Cybersecurity Development (SecDev)*, pp. 45–52, 2016, doi: 10.1109/SecDev.2016.019.

[3] L. Sassaman, M. L. Patterson, and S. Bratus, “A Patch for Postel’s Robustness Principle,” *IEEE Security & Privacy*, vol. 10, no. 2, pp. 87–91, 2012, doi: 10.1109/MSP.2012.31.

[4] S. Ali, P. Anantharaman, Z. Lucas, and S. W. Smith, “What We Have Here Is Failure to Validate: Summer of LangSec,” *IEEE Security & Privacy*, vol. 19, no. 3, pp. 17–23, 2021, doi: 10.1109/MSEC.2021.3059167.

[5] P. Cousot and R. Cousot, “Abstract Interpretation: A Unified Lattice Model for Static Analysis of Programs by Construction or Approximation of Fixpoints,” in *Proceedings of the 4th ACM SIGACT-SIGPLAN Symposium on Principles of Programming Languages (POPL ’77)*, pp. 238–252, 1977, doi: 10.1145/512950.512973.

[6] Linux Kernel Documentation, “Running BPF Programs from Userspace,” [Online]. Available: https://www.kernel.org/doc/html/v6.17/bpf/bpf_prog_run.html (accessed Jul. 11, 2026).

[7] Linux Kernel Documentation, “Program Types and ELF Sections,” [Online]. Available: https://www.kernel.org/doc/html/v6.17/bpf/libbpf/program_types.html (accessed Jul. 11, 2026).

[8] Linux Kernel Documentation, “BPF_MAP_TYPE_HASH, with PERCPU and LRU Variants,” [Online]. Available: https://www.kernel.org/doc/html/v6.17/bpf/map_hash.html (accessed Jul. 11, 2026).

[9] Linux Kernel Documentation, “eBPF Verifier,” [Online]. Available: https://www.kernel.org/doc/html/v6.17/bpf/verifier.html (accessed Jul. 11, 2026).

[10] I. Palmer, E. Rogers, and R. Adams, “Object-Centric Tracing for Language-Theoretic Security in Low-Level Interfaces,” in *Twelfth Workshop on Language-Theoretic Security (LangSec 2026), IEEE Security and Privacy Workshops*, 2026. [Online]. Available: https://langsec.org/spw26/papers/palmer-object-tracing.pdf (accessed Jul. 12, 2026).

[11] S. Bratus, M. E. Locasto, M. L. Patterson, L. Sassaman, and A. Shubina, “Exploit Programming: From Buffer Overflows to Weird Machines and Theory of Computation,” *USENIX ;login:*, vol. 36, no. 6, pp. 13–21, 2011.

[12] J. Bangert, S. Bratus, R. Shapiro, and S. W. Smith, “The Page-Fault Weird Machine: Lessons in Instruction-less Computation,” in *7th USENIX Workshop on Offensive Technologies (WOOT 13)*, 2013.

[13] R. Shapiro, S. Bratus, and S. W. Smith, “‘Weird Machines’ in ELF: A Spotlight on the Underappreciated Metadata,” in *7th USENIX Workshop on Offensive Technologies (WOOT 13)*, 2013.

[14] T. Dullien, “Weird Machines, Exploitability, and Provable Unexploitability,” *IEEE Transactions on Emerging Topics in Computing*, vol. 8, no. 2, pp. 391–403, 2020, doi: 10.1109/TETC.2017.2785299.

[15] J. Paykin, E. Mertens, M. Tullsen, L. Maurer, B. Razet, A. Bakst, and S. Moore, “Weird Machines as Insecure Compilation,” arXiv:1911.00157, 2019.

[16] J. Vanegue, “The Weird Machines in Proof-Carrying Code,” in *2014 IEEE Security and Privacy Workshops*, pp. 209–213, 2014, doi: 10.1109/SPW.2014.37.

[17] R. Giacobazzi, F. Ranzato, and F. Scozzari, “Making Abstract Interpretations Complete,” *Journal of the ACM*, vol. 47, no. 2, pp. 361–416, 2000, doi: 10.1145/333979.333989.

[18] E. Gershuni, N. Amit, A. Gurfinkel, N. Narodytska, J. A. Navas, N. Rinetzky, L. Ryzhyk, and M. Sagiv, “Simple and Precise Static Analysis of Untrusted Linux Kernel Extensions,” in *Proceedings of the 40th ACM SIGPLAN Conference on Programming Language Design and Implementation (PLDI ’19)*, pp. 1069–1084, 2019, doi: 10.1145/3314221.3314590.

[19] H. Vishwanathan, M. Shachnai, S. Narayana, and S. Nagarakatte, “Sound, Precise, and Fast Abstract Interpretation with Tristate Numbers,” in *2022 IEEE/ACM International Symposium on Code Generation and Optimization (CGO)*, pp. 254–265, 2022, doi: 10.1109/CGO53902.2022.9741267.

[20] H. Lu, S. Wang, Y. Wu, W. He, and F. Zhang, “MOAT: Towards Safe BPF Kernel Extension,” in *33rd USENIX Security Symposium (USENIX Security 24)*, pp. 1153–1170, 2024. [Online]. Available: https://www.usenix.org/conference/usenixsecurity24/presentation/lu-hongyi (accessed Jul. 11, 2026).

[21] P. Anantharaman, V. Kothari, J. P. Brady, I. R. Jenkins, S. Ali, M. C. Millian, R. Koppel, J. Blythe, S. Bratus, and S. W. Smith, “Mismorphism: The Heart of the Weird Machine,” in *Security Protocols XXVII*, Lecture Notes in Computer Science, vol. 12287, pp. 113–124, Springer, 2020, doi: 10.1007/978-3-030-57043-9_11.
