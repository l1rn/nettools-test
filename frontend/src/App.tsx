import { useEffect, useState } from "react"

interface Packet {
  src_ip: string;
  dst_ip: string;
  src_port: string;
  dst_port: string;
  protocol: string;
}
function App() {
  const [packets, setPackets] = useState<Packet[]>([]);
  useEffect(() => {
    const socketURL = 'ws://localhost:8080/ws';

    const ws = new WebSocket(socketURL)
    ws.onopen = () => console.log("Connected")

    ws.onmessage = (e) => {
      const packet = JSON.parse(e.data)
      console.log("packet: ", packet)
      setPackets(prev => [packet, ...prev.slice(0, 9)])
    };

    ws.onerror = (e) => console.error("Error: ", e)
    ws.onclose = () => console.log("Closed")
    
    return () => ws.close();
  }, [])
  return (
    <>
      <div>hello</div>
    </>
  )
}

export default App
