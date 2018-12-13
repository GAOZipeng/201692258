# 201692258
DSR路由协议有两个主要机制组成——路由寻找(Route Discovery）机制和路由维护(RouteMaintenance)机制。
路由寻找机制在源节点需要给目的节点发送一个分组并且还不知道到达目的节点的路由的时候使用。
当源节点正在使用一条到达目的节点的源路由的时候，源节点使用路由维护机制可以检测出因为拓扑变化不能使用的路由，当路由维护指出一条源路由已经中断而不再起作用的时候，为了将随后的数据分组传输到目的节点，源节点能够尽力使用一条偶然获知的到达目的节点的路由，或者重新调用路由寻找机制找到一条新路由。
