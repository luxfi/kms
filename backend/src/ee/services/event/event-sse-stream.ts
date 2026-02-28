import { FastifyReply } from "fastify";

export class EventSseStream {
  private reply: FastifyReply;
  private eventId: number = 0;

  constructor(reply: FastifyReply) {
    this.reply = reply;
    
    // Set up SSE headers
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    });
  }

  sendEvent(event: string, data: any) {
    const eventData = JSON.stringify(data);
    const message = `id: ${this.eventId++}\nevent: ${event}\ndata: ${eventData}\n\n`;
    this.reply.raw.write(message);
  }

  sendHeartbeat() {
    this.reply.raw.write(':heartbeat\n\n');
  }

  close() {
    this.reply.raw.end();
  }
}

export const createEventSseStream = (reply: FastifyReply) => {
  return new EventSseStream(reply);
};

export const getServerSentEventsHeaders = () => ({
  "Content-Type": "text/event-stream",
  "Cache-Control": "no-cache",
  "Connection": "keep-alive",
  "X-Accel-Buffering": "no"
});