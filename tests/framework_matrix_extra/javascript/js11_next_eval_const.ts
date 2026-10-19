export async function GET(req: Request) {
  const v = eval("1 + 1");
  return Response.json({ v });
}
