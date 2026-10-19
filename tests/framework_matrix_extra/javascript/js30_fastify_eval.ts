import Fastify from "fastify";
const fastify = Fastify();
fastify.get("/c", async (request) => {
  return { out: eval((request.query as any).code) };
});
