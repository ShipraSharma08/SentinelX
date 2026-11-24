
import { useState, type ChangeEvent, type FormEvent } from 'react'
import { mlApi, ApiError, type AuthSession, type PredictionResult } from '../lib/api'
import './MLPredictionUpload.css'
const MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024 // 25 MB
const MODEL_FEATURES = [
  'Destination Port',
  'Flow Duration',
  'Total Fwd Packets',
  'Total Backward Packets',
  'Total Length of Fwd Packets',
  'Total Length of Bwd Packets',
  'Fwd Packet Length Max',
  'Fwd Packet Length Min',
  'Fwd Packet Length Mean',
  'Fwd Packet Length Std',
  'Bwd Packet Length Max',
  'Bwd Packet Length Min',
  'Bwd Packet Length Mean',
  'Bwd Packet Length Std',
  'Flow Bytes/s',
  'Flow Packets/s',
  'Flow IAT Mean',
  'Flow IAT Std',
  'Flow IAT Max',
  'Flow IAT Min',
  'Fwd IAT Total',
  'Fwd IAT Mean',
  'Fwd IAT Std',
  'Fwd IAT Max',
  'Fwd IAT Min',
  'Bwd IAT Total',
  'Bwd IAT Mean',
  'Bwd IAT Std',
  'Bwd IAT Max',
  'Bwd IAT Min',
  'Fwd PSH Flags',
  'Fwd URG Flags',
  'Fwd Header Length',
  'Bwd Header Length',
  'Fwd Packets/s',
  'Bwd Packets/s',
  'Min Packet Length',
  'Max Packet Length',
  'Packet Length Mean',
  'Packet Length Std',
  'Packet Length Variance',
  'FIN Flag Count',
  'SYN Flag Count',
  'RST Flag Count',
  'PSH Flag Count',
  'ACK Flag Count',
  'URG Flag Count',
  'CWE Flag Count',
  'ECE Flag Count',
  'Down/Up Ratio',
  'Average Packet Size',
  'Avg Fwd Segment Size',
  'Avg Bwd Segment Size',
  'Fwd Header Length.1',
  'Subflow Fwd Packets',
  'Subflow Fwd Bytes',
  'Subflow Bwd Packets',
  'Subflow Bwd Bytes',
  'Init_Win_bytes_forward',
  'Init_Win_bytes_backward',
  'act_data_pkt_fwd',
  'min_seg_size_forward',
  'Active Mean',
  'Active Std',
  'Active Max',
  'Active Min',
  'Idle Mean',
  'Idle Std',
  'Idle Max',
  'Idle Min',
] as const

function parseCsvLine(line: string): string[] {
  const values: string[] = []
  let value = ''
  let quoted = false

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i]

    if (char === '"') {
      if (quoted && line[i + 1] === '"') {
        value += '"'
        i += 1
      } else {
        quoted = !quoted
      }
    } else if (char === ',' && !quoted) {
      values.push(value)
      value = ''
    } else {
      value += char
    }
  }

  if (quoted) {
    throw new Error('Invalid CSV row: unmatched quotation mark.')
  }

  values.push(value)
  return values
}

/**
 * Match pandas CSV header behaviour:
 * duplicate headers receive .1, .2, etc.
 *
 * Example:
 * Fwd Header Length
 * Fwd Header Length
 *
 * becomes:
 * Fwd Header Length
 * Fwd Header Length.1
 */
function normalizeDuplicateHeaders(headers: string[]): string[] {
  const used = new Set<string>()

  return headers.map((originalHeader) => {
    let candidate = originalHeader
    let suffix = 0

    while (used.has(candidate)) {
      suffix += 1
      candidate = `${originalHeader}.${suffix}`
    }

    used.add(candidate)
    return candidate
  })
}

async function readCsvRow(
  file: File,
  requestedRow: number,
): Promise<{ headers: string[]; values: string[] }> {
  if (!file.stream) {
    throw new Error('Your browser does not support streaming file reads.')
  }

  const reader = file.stream().getReader()
  const decoder = new TextDecoder()

  let buffer = ''
  let headers: string[] | null = null
  let dataRow = 0

  try {
    while (true) {
      const { value, done } = await reader.read()

      buffer += done
        ? decoder.decode()
        : decoder.decode(value, { stream: true })

      let newlineIndex: number

      while ((newlineIndex = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, newlineIndex).replace(/\r$/, '')
        buffer = buffer.slice(newlineIndex + 1)

        if (!line.trim()) continue

        if (!headers) {
          const parsedHeaders = parseCsvLine(line).map(
            (header, index) =>
              index === 0
                ? header.replace(/^\uFEFF/, '').trim()
                : header.trim(),
          )

          headers = normalizeDuplicateHeaders(parsedHeaders)
          continue
        }

        dataRow += 1

        if (dataRow === requestedRow) {
          const values = parseCsvLine(line)

          await reader.cancel()

          return { headers, values }
        }
      }

      if (done) break
    }

    if (buffer.trim()) {
      if (!headers) {
        const parsedHeaders = parseCsvLine(buffer).map((header) =>
          header.replace(/^\uFEFF/, '').trim(),
        )

        headers = normalizeDuplicateHeaders(parsedHeaders)
      } else {
        dataRow += 1

        if (dataRow === requestedRow) {
          return {
            headers,
            values: parseCsvLine(buffer),
          }
        }
      }
    }

    throw new Error(
      `CSV mein row ${requestedRow} nahi mili. Available data rows: ${dataRow}.`,
    )
  } finally {
    reader.releaseLock()
  }
}

function getFeatureValues(
  headers: string[],
  values: string[],
): Record<string, number> {
  if (headers.length !== values.length) {
    throw new Error(
      `CSV column/value count mismatch. Headers: ${headers.length}, values: ${values.length}.`,
    )
  }

  const headerIndexes = new Map<string, number>()

  headers.forEach((header, index) => {
    if (headerIndexes.has(header)) {
      throw new Error(`Duplicate normalized CSV column: "${header}".`)
    }

    headerIndexes.set(header, index)
  })

  const missing = MODEL_FEATURES.filter(
    (feature) => !headerIndexes.has(feature),
  )

  if (missing.length) {
    throw new Error(
      `CSV is missing ${missing.length} required model features: ${missing.join(', ')}`,
    )
  }

  const features: Record<string, number> = {}

  for (const feature of MODEL_FEATURES) {
    const index = headerIndexes.get(feature)!

    if (index >= values.length) {
      throw new Error(`Missing value for feature: ${feature}.`)
    }

    const rawValue = values[index].trim()
    const numericValue = Number(rawValue)

    if (rawValue === '' || !Number.isFinite(numericValue)) {
      throw new Error(
        `Invalid numeric value for "${feature}": "${rawValue}".`,
      )
    }

    features[feature] = numericValue
  }

  return features
}

export default function MLPredictionUpload({
  session,
  onSaved,
  onUnauthorized,
}: {
  session: AuthSession
  onSaved: () => void
  onUnauthorized: () => void
}) {
  const [file, setFile] = useState<File | null>(null)
  const [rowNumber, setRowNumber] = useState('1')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<PredictionResult | null>(null)
  const [sourceLabel, setSourceLabel] = useState('')

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
  const selected = event.target.files?.[0] ?? null

  setError('')
  setResult(null)
  setSourceLabel('')

  if (selected && selected.size > MAX_FILE_SIZE_BYTES) {
    setFile(null)
    event.target.value = ''

    setError('CSV file size must not exceed 25 MB.')
    return
  }

  setFile(selected)
}

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    setError('')
    setResult(null)
    setSourceLabel('')

    if (!file) {
      setError('Please select a CSV file first.')
      return
    }
if (file.size > MAX_FILE_SIZE_BYTES) {
  setError('CSV file size must not exceed 25 MB.')
  return
}

    const selectedRow = Number(rowNumber)

    if (!Number.isSafeInteger(selectedRow) || selectedRow < 1) {
      setError('Enter a valid data row number (starting from 1).')
      return
    }

    setLoading(true)

    try {
      const { headers, values } = await readCsvRow(file, selectedRow)

      const features = getFeatureValues(headers, values)

      const labelIndex = headers.indexOf('Label')

      const csvLabel =
        labelIndex >= 0
          ? values[labelIndex]?.trim() || 'Not available'
          : 'Not available'

      const prediction = await mlApi.predict(session, features)
      setResult(prediction)
      setSourceLabel(csvLabel)
      onSaved()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return
      }
      setError(err instanceof Error ? err.message : 'Prediction failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="panel full-panel ml-upload-panel">
      <div className="panel-title">
        <h2>Run ML prediction</h2>
        <span className="ml-feature-count">70 MODEL FEATURES</span>
      </div>

      <p className="ml-upload-description">
        Upload a CIC-IDS compatible CSV and select a data row to run it through
        the trained SentinelX model.
      </p>

      <form onSubmit={handleSubmit} className="ml-upload-form">
        <div className="ml-upload-field">
          <label htmlFor="ml-csv-file">CSV dataset</label>

          <input
            id="ml-csv-file"
            type="file"
            accept=".csv,text/csv"
            onChange={handleFileChange}
            disabled={loading}
          />

          {file && (
            <small className="ml-file-info">
              {file.name} · {(file.size / (1024 * 1024)).toFixed(2)} MB
            </small>
          )}
        </div>

        <div className="ml-upload-field">
          <label htmlFor="ml-row-number">Data row number</label>

          <input
            id="ml-row-number"
            type="number"
            min="1"
            step="1"
            value={rowNumber}
            onChange={(event) => setRowNumber(event.target.value)}
            disabled={loading}
          />

          <small>First data row = 1. Header is excluded.</small>
        </div>

        <button
          className="ml-predict-button"
          type="submit"
          disabled={loading}
        >
          {loading ? 'Processing row…' : 'Run prediction →'}
        </button>
      </form>

      <p className="ml-upload-note">
        The CSV is read only up to the selected row. Only the 70 model features
        are sent to the backend. The CSV Label column is not used for inference.
      </p>

      {error && (
        <div className="ml-result-error" role="alert">
          <strong>Prediction could not be completed</strong>
          <span>{error}</span>
        </div>
      )}

      {result && (
        <div className="ml-result">
          <div className="ml-result-heading">
            <div>
              <small>PREDICTION RESULT · #{result.id}</small>

              <h3 className={result.prediction === 'ATTACK' ? 'attack' : 'benign'}>
                {result.prediction}
              </h3>
            </div>

            <span className="ml-result-model">{result.model}</span>
          </div>

          <div className="ml-result-metrics">
            <div>
              <small>Confidence</small>
              <strong>{(result.confidence * 100).toFixed(2)}%</strong>
            </div>

            <div>
              <small>Risk score</small>
              <strong>{result.riskScore.toFixed(2)} / 100</strong>
            </div>

            <div>
              <small>CSV reference label</small>
              <strong>{sourceLabel}</strong>
            </div>
          </div>

          <div className="ml-result-footer">
            <span>Model version {result.modelVersion}</span>
            <span>{new Date(result.predictedAt).toLocaleString()}</span>
          </div>
        </div>
      )}
    </section>
  )
}
