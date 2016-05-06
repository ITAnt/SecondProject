1	需求背景
详细请参考Cloud3.0 HOSS部分特性说明。
1.       采集维度：访问时延为单位时间内平均时延，而且工具的单位时间可调，以适应我们的离线分析和在线分析功能
2.       数据形式：在某计算资源量容器下，访问时延指标存储的是单个数据点；QPS存储的是数据曲线(数据集合)，必须包含当前计算资源量下的最大QPS
3.       输出接口：采集的数据输出到数据库进行持久化存储
1、	当前只需要采集基于K8S上的容器的QPS和时延指标，统计周期可配置，最小1秒，其中时延指标为统计周期内的平均时延。
2、	采集到的数据保存在数据库，暂不需提供外部查询API，外面可以从数据库导出文件的方式获取数据。
3、	采集目标的应用/服务名称因涉及与K8S交互，采集工具暂时只提供IP地址，由外面通过应用部署信息获取对应的应用名称。

2	整体方案
 

备选方案1：
在Node节点上部署vProbe，采集节点上所有的容器的流量，该方案需要获取当前所有容器的网口信息，并且需要感知容器的上线和下线，与K8S耦合紧密，而且容易受容器的不同网络方案影响。
备选方案2：
采用类似sysDig的方案，在Node节点上通过深度侵入OS内核的方式获取容器的内部流量和事件，该方法技术难度大且对OS侵入较深，不推荐。

方案对比
	方案1：Pod内置vProbe	方案2：Pod外置vProbe
性能	只监控单个Pod，性能可控	监控多个Pod，Pod数量不定，性能不可控
资源消耗	单个Pod：内存：10M，CPU：<5%	单个Pod：需要同步Pod信息，资源消耗会略有提高
实现复杂度	实现简单，只负责本地网口数据采集与处理，功能独立单一，不参与其他非探针工作处理，不与外部系统耦合，流量低，可单线程处理，与单机处理程序类似。	实现复杂，需要并行采集多个Pod网口的数据，数据流量大，需要多线程处理，方案实现复杂，容易出问题，与K8S同步Pod信息，依赖外部组网方案，与外部系统耦合高。
独立性	独立性好，与外部系统不耦合	独立性差，需要与外部环境交互
部署	优点：
可以随业务Pod分布式部署、弹性伸缩和HA保障
缺点：
需要把vProbe容器内嵌到业务Pod环境内，需要容器编排支持。	优点：
在节点部署，对用户Pod无侵入
缺点：
需要与K8S同步Pod信息以便确定采集哪些流量
3	方案说明
3.1	数据采集
数据采集由vProbe完成，vProbe由Collector、PSR和Metrics三个模块组成，分别完成流量采集、数据解析和监控指标计算上报的功能。
3.1.1	流量采集（Collector）
在K8S的POD内部署流量采集探针vProbe，实现对POD流量的采集。因为K8S的POD内容器共享同一个网络namespace，各个容器（包括vProbe所在的容器）看到的网卡都是相同的，因此在vProbe容器内通过侦听指定的虚拟网卡接口（一般是eth0）就可以实现对POD出入口流量的监控和采集。
实现方式：vProbe创建PF_PACKET类socket，侦听POD的网卡流量，实现对链路层以上数据的采集，如下：
packet_socket = socket(PF_PACKET, int socket_type, int protocol);
PF_Packet套接字的数据收集和传输层套接字的数据收集大同小异。具体如下:
首先创建socket和绑定到本地的套接字数据空间。
 
然后调用recvform采集从链路层来的数据包，进行进行解析。
 

为了减少流量采集数量，Collector需要支持流量过滤功能，过滤策略可配置，比如通过L2/L4/L7协议过滤、端口过滤。因为本需求需要计算Web类应用的QPS和访问时延，只需要对访问本端的HTTP流量做处理，因此过滤策略为：外部发起的TCP请求链接 & HTTP协议，其中：外部发起的TCP链接可以通过本端IP地址以及IP包的L4协议类型来过滤，本地IP地址可以通过外部配置或本地读接口的方式获取(如ioctl)，HTTP协议可以用80、8080端口简单过滤，后期可以集成DPI技术识别过滤。
同时，Collector需要支持采样机制，可设置采样率，根据采样率对数据流进行采样。
Collector输出的数据包信息包括：五元组、时间戳、报文长度、报文内容，协议类型（当前只处理HTTP）。
3.1.2	数据解析（PSR）
Collector把流量采集上来之后先通过PSR模块进行解析，获取HTTP请求和响应标识，记录每个请求和响应包上的时间戳，PSR模块将解析之后的结果以事务为单元组织缓存起来并发送到Metrics模块，事务信息包括：
Transaction{
	Request{
		Timestamp: Integer32
}
Response{
	Timestamp: Integer32
	Code: Integer16
	}
}
注意：不完整的事务如只有请求没有响应的事务作为异常事务需要统计输出，PSR需要启动定时器跟踪每个请求的状态，超时时间根据配置获取。
PSR需要支持HTTP的PIPELINE场景，
3.1.3	指标计算（Metrics）
Metrics模块负责汇聚缓存事务信息并定期输出到ops-agent，由外部分析系统统计QPS和时延，Metrics到ops-agent的上报周期可以为30s或其他值，可配置，范围为1-60s，ops-agent到kafka的上报周期以分钟为粒度，可配置，范围为1-5分钟。上报的内容为本周期内产生的事务统计信息。一条记录的结构如下：
Metric{
	Transaction number: Ingeger32 //正常事务个数，与下面的list个数一致
	List transaction[
		Transaction{
			Start timestamp：Integer32//请求接收时间戳，单位s
			Latency：Integer16 //响应时延，单位ms
			Code：Integer16 //响应码
		}
	]
	Error transaction number: Integer32 //异常事务个数，每个周期只上报一次
}
3.2	数据传输与存储
数据传输分两个阶段，阶段一是从vProbe到ops-agent，阶段二是从ops-agent到后台数据库，对于阶段一，有两种方法，第一种方法是日志的方式，具体是vProbe调用stdout写日志到指定的文件目录，该目录mount到外部主机设置的log目录，由log采集工具如fluentd统一采集上报，需要fluentd区分QPS、时延与其他普通日志；第二种方法是vProbe直接发给ops-agent，需要ops-agent支持接收QPS和时延数据并转发到后台，同时在启动ops-agent时把ops-agent的IP和端口写到配置文件，以通知vProbe，ops-agent必须在vProbe之前启动。建议采用第二种方法。
对于阶段二，沿用当前kafka->metric-bridge->opentsdb的架构，QPS和时延信息保存在opentsdb数据库。
4	性能
Metrics需要缓存最大1分钟的数据，可以根据实际吞吐量调整，按核心网评估的数据，一个VM约14个服务实例，共产生3500TPS，极端情况下假如都是接收产生的，每个服务实例平均约3500/14=250TPS，因此1分钟需要缓存的事务数约60*250=15000，内存消耗约12*15000=180Kbytes，占用的带宽约180K/60=3KBPS。核心网1100个服务实例规模的话，整个集群的Metric吞吐量为12*250*1100=3.3MBPS。
按业软1W微服务，10W服务实例的规模，每个服务实例按100TPS计算（待和业软确定），吞吐量为12*100*100000=114MBPS。
5	可靠性
vProbe容器需要通过K8S的health check机制来保证持续运行，如果vProbe运行中出问题能及时重启容器。
6	依赖与约束
	因为需要在业务Pod内嵌入vProbe容器，需要CCE部署Pod的时候可以把vProbe容器自动添加到业务Pod内，并保证ops-agent容器必须在其他业务Pod启动之前启动。
	不支持HTTPS访问方式的统计。
7	工作量评估
数据采集：0.2K
数据处理：
1）	IP乱序重组：0.5K
2）	流表管理：0.5K
3）	流量识别、采样、过滤：0.2K
4）	HTTP请求/响应关联：0.8K
运行配置：0.1K
数据传输：
1）	vProbe到ops-agent：0.5K
2）	ops-agent到Kafka：0.1K
数据存储：
1）Kafka到hbase：0.1K

共3K工作量
