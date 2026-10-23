import { exec } from "child_process";

// Command injection: the query string goes straight into a shell.
export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q");
  return new Promise((resolve) => {
    exec(`grep -r ${q} ./content`, (_err, stdout) => {
      resolve(Response.json({ hits: stdout }));
    });
  });
}
