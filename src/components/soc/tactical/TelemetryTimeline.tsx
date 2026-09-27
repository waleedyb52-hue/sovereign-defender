import React from 'react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

/**
 * TELEMETRY TIMELINE — recharts AreaChart with cyan gradients.
 *
 * Two series, both real: requests per second and threats, from `frequencyGraph`.
 *
 * `type="linear"` rather than a monotone or basis curve, deliberately. A smoothing
 * spline moves the rendered line off the sampled values to look pleasant, and on a
 * traffic chart that means a spike is drawn slightly lower and slightly later than it
 * happened. Every point here sits exactly where it was measured; the gradient fill does
 * the visual work instead.
 *
 * Below two samples the chart is not drawn at all. One point rendered as a flat line is
 * a claim about stability that a single observation cannot support.
 */

export interface TimelinePoint {
  label: string;
  value: number;
  threats: number;
}

export const TelemetryTimeline: React.FC<{
  points: TimelinePoint[];
  isAr: boolean;
  height?: number;
  endpoint?: string;
}> = ({ points, isAr, height = 128, endpoint = '/soc/analytics' }) => {
  if (points.length < 2) {
    return (
      <div className="grid place-items-center" style={{ height }}>
        <div className="text-center">
          <p className="font-mono text-[7.5px] leading-relaxed text-slate-500">
            {isAr
              ? 'نقطتان على الأقل لازمتان لرسم اتجاه. عيّنة واحدة كخطٍّ مستقيم ادّعاءُ استقرارٍ لا تحمله ملاحظة واحدة.'
              : 'a trend needs at least two samples. one point drawn flat is a stability claim a single observation cannot support.'}
          </p>
          <p className="mt-1 font-mono text-[6.5px] text-slate-700">{endpoint}</p>
        </div>
      </div>
    );
  }

  return (
    <div style={{ height }} className="mt-1">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={points} margin={{ top: 4, right: 4, left: -22, bottom: 0 }}>
          <defs>
            <linearGradient id="tl-rps" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.55} />
              <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="tl-threat" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#e11d48" stopOpacity={0.5} />
              <stop offset="100%" stopColor="#e11d48" stopOpacity={0} />
            </linearGradient>
          </defs>

          <CartesianGrid stroke="rgba(34,211,238,0.07)" vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fill: '#475569', fontSize: 6, fontFamily: 'var(--font-mono)' }}
            stroke="rgba(34,211,238,0.15)"
            interval="preserveStartEnd"
            minTickGap={24}
          />
          <YAxis
            tick={{ fill: '#475569', fontSize: 6, fontFamily: 'var(--font-mono)' }}
            stroke="rgba(34,211,238,0.15)"
            width={36}
          />
          <Tooltip
            contentStyle={{
              background: 'rgba(3,7,18,0.92)',
              border: '1px solid rgba(34,211,238,0.4)',
              borderRadius: 2,
              boxShadow: '0 0 20px rgba(0,0,0,0.85)',
              fontFamily: 'var(--font-mono)',
              fontSize: 9
            }}
            labelStyle={{ color: '#22d3ee', fontSize: 8 }}
            itemStyle={{ fontSize: 8 }}
          />
          <Area
            type="linear"
            dataKey="value"
            name={isAr ? 'طلب/ث' : 'RPS'}
            stroke="#22d3ee"
            strokeWidth={1.4}
            fill="url(#tl-rps)"
            dot={false}
            activeDot={{ r: 2.5, fill: '#22d3ee' }}
            isAnimationActive={false}
          />
          <Area
            type="linear"
            dataKey="threats"
            name={isAr ? 'تهديدات' : 'THREATS'}
            stroke="#e11d48"
            strokeWidth={1.4}
            fill="url(#tl-threat)"
            dot={false}
            activeDot={{ r: 2.5, fill: '#e11d48' }}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

export default TelemetryTimeline;
