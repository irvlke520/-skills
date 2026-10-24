# 反射、名称与对象结构

## 确定结构来源

先用匹配源码、PDB、反射导出或反汇编确认具体布局。`UObject → UClass/UStruct → 属性/函数` 是语义关系，不是一份可直接强转任意内存的 C 结构定义。Shipping、Editor、平台、编译选项和项目分支都可能影响布局。

有源码或可用调试环境时，优先读实际类型和访问接口。只有原始字节时，记录候选成员的地址基准、宽度、上下文和反例，再逐项验证；不从互联网复制一组通用 `GWorld/GNames/GObjects` 偏移。

## UObject 与对象容器

把对象身份、Class、Outer、标志和存活状态分别核对。Outer 表示包含关系，不能单独当成“对象一定被强引用”的证明；地址非零也不等于对象仍有效。

`GUObjectArray` 的语义、对象项和分块表需要分别辨认。对分块实现核对元素数、块数、块容量和对象项大小，再通过索引定位对象项；不要把 `FUObjectItem**` 直接当成连续对象数组。弱引用还需对应的身份/序列信息，索引有效不能证明原对象尚未被回收或替换。

UE5 的 `TObjectPtr`、弱引用和软引用各有含义。不要把所有包装类型都当作一个可以立即解引用的裸地址；软引用可能只有资产路径。准确解释引用是否保持对象存活时，同时核对它是否被反射/GC 跟踪及实际使用场景。

## FName

名称不是一根通用字符串指针。先确认实际名称存储和 entry 编码，区分索引、比较/显示身份以及名称编号；构建选项也可能影响这些字段的表示。

以多个已知类、包路径和带编号实例交叉验证解析，核对 ANSI/宽字符、长度与边界。只解析出一个可读单词不足以证明整个名称表正确。名称编号的内部值与显示后缀不要凭直觉加减；优先对照当前实现或已知输出。不要把正常的名称索引查找称为“解密”。

## UClass、UStruct 与属性

旧版 `UProperty` 与较新版本的 `FProperty/FField` 路径应从目标实际类型确认，不能默认同一继承链和字段偏移。

字段记录至少包含所属类型、类型类别、实例/容器基准、元素大小、固定数组维数与偏移。`ArrayDim` 表示反射属性的固定维数，不是 `TArray` 当前元素数。动态数组、集合与映射需要各自的容器表示。

`FBoolProperty` 需要额外确认字节偏移与掩码；位域布尔不能只用“基址加字段偏移后读一个 bool”解释。嵌套结构、继承成员、对象引用和容器元素的基准也应分别记录。拥有可编译匹配源码时，可以用属性访问接口核对；离线转储中的候选偏移仍要由字节与消费者指令验证。

CDO 是类默认对象，不是任意运行中实例。将默认值、关卡序列化覆盖值和运行时修改区分开，避免把 CDO 中的一份状态报告为所有对象的当前状态。

## UFunction、蓝图与调用分发

先确认用户要解释的是函数定义、调用入口还是运行中的参数值。UFunction 反射数据、native thunk、本机实现和脚本路径不一定一一对应；沿调用关系分析实际实现。

参数缓冲区应依据当前函数的参数属性、标志、`ParmsSize`、对齐和返回属性解释。区分值参数、引用/输出参数和返回值；不要把参数区当作一串等宽指针，也不把它的属性偏移当成 UObject 实例偏移。

`ProcessEvent` 是分析调用分发的线索，不是每项任务都要安装 Hook 的要求。静态分析时追踪调用者和分发路径；有实际调试证据时再关联函数身份、线程和参数。未主动调用过就不报告调用成功，也不为了查看签名触发 RPC 或改变运行状态。

## 依据

对应 Epic API：[FProperty](https://dev.epicgames.com/documentation/en-us/unreal-engine/API/Runtime/CoreUObject/FProperty)、[FBoolProperty](https://dev.epicgames.com/documentation/en-us/unreal-engine/API/Runtime/CoreUObject/FBoolProperty)、[UFunction](https://dev.epicgames.com/documentation/en-us/unreal-engine/API/Runtime/CoreUObject/UFunction)、[FName](https://dev.epicgames.com/documentation/en-us/unreal-engine/API/Runtime/Core/FName)、[FChunkedFixedUObjectArray](https://dev.epicgames.com/documentation/en-us/unreal-engine/API/Runtime/CoreUObject/FChunkedFixedUObjectArray)。引用语义参见 [Object Pointers](https://dev.epicgames.com/documentation/en-us/unreal-engine/object-pointers-in-unreal-engine)；地址布局以目标版本和构建为准。
