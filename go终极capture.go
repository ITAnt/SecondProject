package main

import (
  "time"
  "github.com/google/gopacket/pcap"
  "log"
  "fmt"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "strings"
  "vprobe/rawtransaction"
  "sync"
  "encoding/json"
  "vprobe/metric"
)

var (
  device string = "eth1"
  snapshot_len int32 = 1024
  promiscuous bool = false
  timeout time.Duration = 30 * time.Second
  handle *pcap.Handle
  localAddress string
  errorNumber int = 0

  channel chan bool = make(chan bool)

  lock = &sync.RWMutex{}
  // Metrics到ops-agent的上报周期(30s)或其他值，可配置，范围为1-60s
  // ops-agent到kafka的上报周期以分钟为粒度，可配置，范围为1-5分钟
  noresp int = 30000 // 指标上报周期为30秒，即30000毫秒
  requestList []rawtransaction.RequestIdentification = make([]rawtransaction.RequestIdentification, 0, 50) // 30个元素，预留20个元素

  rawTransactions []rawtransaction.Transaction = make([]rawtransaction.Transaction, 0, 50) // 未处理的事务

  transactionList []metric.Transaction = make([]metric.Transaction, 0, 50) // 经过处理的事务
)

func main() {
  // 查找设备
  devices, err := pcap.FindAllDevs()
  if err != nil {
    log.Fatal(err)
  }

  MainThread:
  for _, dev := range devices {
    if strings.EqualFold(dev.Name, device) {
      for _, address := range dev.Addresses {
        // 获取到了本地IP
        localAddress = address.IP.To4().String()
        break MainThread
      }
    }
  }

  // 每隔30秒统计一次
  go capturePacket(err)
  go submitTrans()
  go formMetrics()

  <-channel
}

/**
 * 抓取报文
 */
func capturePacket(err error) {
  // 实时监控
  handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
  if err != nil {
    log.Fatal(err)
  }
  defer handle.Close()

  // 设置过滤80==========================80端口
  var filter string = "tcp and port 22"
  err = handle.SetBPFFilter(filter)
  if err != nil {
    log.Fatal(err)
  }

  fmt.Println("Only capturing TCP port 80 packets.")
  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  for packet := range packetSource.Packets() {
    //fmt.Println()
    //fmt.Println("============packet start=========")
    // 直接打印抓到的数据包
    //fmt.Println(packet)


    // 打印解析之后的数据包信息
    printPacketInfo(packet)
    //fmt.Println("============packet end===========")
  }
  channel <- true
}

/**
 * 解析报文
 */
func printPacketInfo(packet gopacket.Packet) {
  //fmt.Println("有报文")
  ipLayer := packet.Layer(layers.LayerTypeIPv4)
  if ipLayer != nil {
    // 包含IP包
    //fmt.Println("有IP")
    ip, _ := ipLayer.(*layers.IPv4)

    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer != nil {
      // 包含TCP包
      tcp, _ := tcpLayer.(*layers.TCP)
      applicationLayer := packet.ApplicationLayer()
      //fmt.Println("有TCP")

      //fmt.Println("协议类型： ", ip.Protocol)
      //fmt.Printf("源IP地址：%s -----目的IP地址：%s\n", ip.SrcIP, ip.DstIP)
      //fmt.Printf("源端口：%d --------目的端口：%d\n", tcp.SrcPort, tcp.DstPort)
      // 时间戳
      timestamp := int(packet.Metadata().Timestamp.Unix())
      //fmt.Println("时间戳：" + timestamp)
      // 报文内容
      //packetContent := packet.Data()
      //fmt.Println("报文内容：" + string(packetContent))
      // 报文总长度
      //packetLength := packet.Metadata().CaptureLength
      //fmt.Println("报文长度：" + strconv.Itoa(packetLength))
      lock.Lock()
      if strings.EqualFold(localAddress, ip.SrcIP.String()) {
        // 这个包代表的是HTTP请求，添加到请求列表
        iden := ip.SrcIP.String() + tcp.SrcPort.String() + ip.DstIP.String() + tcp.DstPort.String()
        reqiden := rawtransaction.RequestIdentification{
          timestamp,
          -1,
          iden,
          false,
          0,
        }
        requestList = append(requestList, reqiden)
        //fmt.Println("请求:" + ip.SrcIP.String() + ":" + tcp.SrcPort.String() + "->" + ip.DstIP.String() + ":" + tcp.DstPort.String())
      } else {
        // 这个包代表的是HTTP响应，查看是否有请求与其对应
        //fmt.Println("响应:" + ip.SrcIP.String() + ":" + tcp.SrcPort.String() + "->" + ip.DstIP.String() + ":" + tcp.DstPort.String())
        iden := ip.DstIP.String() + tcp.DstPort.String() + ip.SrcIP.String() + tcp.SrcPort.String()
        for i, _ := range requestList {
          if strings.EqualFold(requestList[i].Identification, iden) {

            // 那么这个响应就是请求reqiden的
            if timestamp - requestList[i].Timestamp > noresp {
              // 超时了，形成异常事务
            } else {
              // 没有超时，形成正常事务，请求时间戳，响应时间戳，响应码
              requestList[i].Modify = true
              requestList[i].RespTimestamp = timestamp
              requestList[i].Code = 200// 这个要处理==================
            }
          }
        }
      }
      lock.Unlock()


      if applicationLayer != nil {
        if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
          fmt.Println("有HTTP")
        }
      }


    }
  }
}

func submitTrans() {
  c := time.Tick(30 * time.Second)
  for _ = range c {
    // 每隔30秒统计一次
    lock.Lock()
    for _, reqiden := range requestList {
      if reqiden.Modify {
        rawtra := rawtransaction.Transaction {
          rawtransaction.Request{reqiden.Timestamp},
          rawtransaction.Response{reqiden.RespTimestamp, reqiden.Code},
        }
        rawTransactions = append(rawTransactions, rawtra)
      } else {
        // 异常事务+1
        errorNumber++
      }
    }

    // 打印原始事务
    //rawTransactionJson, _ := json.Marshal(rawTransactions)
    //fmt.Println(string(rawTransactionJson))
    lock.Unlock()
  }
}

func formMetrics() {
  // 每隔5分钟搞一次
  c := time.Tick(300 * time.Second)
  for _ = range c {
    // 每隔30秒统计一次

    for _, rawTransaction := range rawTransactions {
      transaction := metric.Transaction{
        rawTransaction.Request.Timestamp,
        rawTransaction.Response.Timestamp - rawTransaction.Request.Timestamp,
        rawTransaction.Response.Code,
      }
      transactionList = append(transactionList, transaction)
    }

    metric := metric.Metric{
      len(transactionList),
      transactionList,
      errorNumber,
    }

    // 打印原始事务
    metricJson, _ := json.Marshal(metric)
    fmt.Println(string(metricJson))

    lock.Lock()
    //操作之后，清空requestList和rawTransactions
    transactionList = transactionList[:0]
    rawTransactions = rawTransactions[:0]
    requestList = requestList[:0]
    errorNumber = 0
    lock.Unlock()
  }
}

