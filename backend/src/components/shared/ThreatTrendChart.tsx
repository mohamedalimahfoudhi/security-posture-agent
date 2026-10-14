import {
  LineChart as RechartsLineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ThreatTrendPoint } from "@/types";

interface ThreatTrendChartProps {
  data: ThreatTrendPoint[];
}

export function ThreatTrendChart({ data }: ThreatTrendChartProps) {
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Threat Trend Over Time</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[280px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <RechartsLineChart data={data} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" />
              <XAxis
                dataKey="date"
                stroke="#6B7280"
                fontSize={11}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                stroke="#6B7280"
                fontSize={11}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#111827",
                  border: "1px solid #1F2937",
                  borderRadius: "6px",
                  fontSize: "12px",
                }}
              />
              <Legend
                wrapperStyle={{ fontSize: "12px", paddingTop: "12px" }}
              />
              <Line
                type="monotone"
                dataKey="critical"
                stroke="#EF4444"
                strokeWidth={2}
                dot={false}
                name="Critical"
              />
              <Line
                type="monotone"
                dataKey="high"
                stroke="#F97316"
                strokeWidth={2}
                dot={false}
                name="High"
              />
              <Line
                type="monotone"
                dataKey="medium"
                stroke="#F59E0B"
                strokeWidth={2}
                dot={false}
                name="Medium"
              />
              <Line
                type="monotone"
                dataKey="low"
                stroke="#2563EB"
                strokeWidth={2}
                dot={false}
                name="Low"
              />
            </RechartsLineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
