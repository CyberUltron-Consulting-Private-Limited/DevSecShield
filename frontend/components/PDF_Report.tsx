"use client";

import { Document, Page, Text, View, pdf } from "@react-pdf/renderer";
import { createTw } from "react-pdf-tailwind";

// Initialize Tailwind for react-pdf
// Uses default Helvetica font that comes with react-pdf
const tw = createTw({
  theme: {
    extend: {
      colors: {
        teal: {
          500: "#14b8a6",
          600: "#0d9488",
        },
        gray: {
          50: "#f9fafb",
          100: "#f3f4f6",
          200: "#e5e7eb",
          300: "#d1d5db",
          400: "#9ca3af",
          500: "#6b7280",
          600: "#4b5563",
          700: "#374151",
          800: "#1f2937",
          900: "#111827",
        },
        red: {
          50: "#fee2e2",
          100: "#fecaca",
          800: "#991b1b",
        },
        yellow: {
          50: "#fef3c7",
          100: "#fef3c7",
          600: "#92400e",
          700: "#78350f",
          800: "#f59e0b",
        },
        blue: {
          50: "#eff6ff",
          100: "#dbeafe",
          200: "#bfdbfe",
          500: "#3b82f6",
          600: "#1e40af",
          700: "#1e3a8a",
        },
        green: {
          50: "#d1fae5",
          500: "#059669",
        },
      },
    },
  },
});

// Define types based on export_generation.py
export type Severity = "Low" | "Medium" | "High" | "Critical";

export interface CVE {
  cve_id: string;
  description: string;
  severity: Severity;
}

export interface Vulnerability {
  name: string;
  description: string;
  code_snippet_or_location?: string | null;
  cves: CVE[];
  severity: Severity;
  fix: string;
}

export interface ExportResults {
  vulnerabilities: Vulnerability[];
}

// Helper function to get severity badge Tailwind classes
const getSeverityClasses = (severity: Severity) => {
  switch (severity) {
    case "Critical":
      return "bg-red-50 text-red-800";
    case "High":
      return "bg-red-100 text-red-800";
    case "Medium":
      return "bg-yellow-50 text-yellow-600";
    case "Low":
      return "bg-blue-100 text-blue-600";
    default:
      return "bg-blue-100 text-blue-600";
  }
};

// Helper function to count vulnerabilities by severity
const countBySeverity = (vulnerabilities: Vulnerability[], severity: Severity) => {
  return vulnerabilities.filter((v) => v.severity === severity).length;
};

// Helper function to chunk array into smaller arrays
const chunkArray = <T,>(array: T[], chunkSize: number): T[][] => {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += chunkSize) {
    chunks.push(array.slice(i, i + chunkSize));
  }
  return chunks;
};

// PDF Document Component
export const PDFDocument = ({ 
  data, 
  scanType = "Security Scan",
  scanTarget,
  scanDate 
}: { 
  data: ExportResults; 
  scanType?: string;
  scanTarget?: string | null; 
  scanDate?: string 
}) => {
  // Debug: Log data to verify structure
  console.log("PDF Data:", JSON.stringify(data, null, 2));
  
  const totalVulnerabilities = data.vulnerabilities.length;
  const criticalCount = countBySeverity(data.vulnerabilities, "Critical");
  const highCount = countBySeverity(data.vulnerabilities, "High");
  const mediumCount = countBySeverity(data.vulnerabilities, "Medium");
  const lowCount = countBySeverity(data.vulnerabilities, "Low");

  // Split vulnerabilities into chunks of 3
  const vulnerabilityChunks = chunkArray(data.vulnerabilities, 3);
  const vulnerabilityPages = vulnerabilityChunks.length;

  // Calculate total pages: 1 (cover) + vulnerability pages
  const totalPages = 1 + vulnerabilityPages;

  return (
    <Document>
      {/* Page 1: Cover Page with Executive Summary */}
      <Page size="A4" style={tw("p-10")}>
        {/* Header */}
        <View style={tw("mb-8 pb-5 border-b-2 border-teal-500")}>
          <Text style={tw("text-3xl font-bold text-teal-500 mb-2")}>{scanType} Report</Text>
          {scanTarget && (
            <Text style={tw("text-sm text-gray-500 mb-1")}>
              {scanType.includes("SAST") ? "Repository" : scanType.includes("LLM") ? "Model" : "Target"}: {scanTarget}
            </Text>
          )}
          <Text style={tw("text-sm text-gray-500 mb-1")}>Scan Date: {scanDate || new Date().toLocaleDateString()}</Text>
        </View>

        {/* Executive Summary */}
        <View style={tw("p-4 bg-blue-50 rounded border border-blue-200 mb-5")}>
          <Text style={tw("text-sm font-bold text-blue-600 mb-2")}>Executive Summary</Text>
          <Text style={tw("text-xs text-blue-700 mb-1")}>Total Vulnerabilities: {totalVulnerabilities}</Text>
          <Text style={tw("text-xs text-blue-700 mb-1")}>Critical: {criticalCount}</Text>
          <Text style={tw("text-xs text-blue-700 mb-1")}>High: {highCount}</Text>
          <Text style={tw("text-xs text-blue-700 mb-1")}>Medium: {mediumCount}</Text>
          <Text style={tw("text-xs text-blue-700 mb-1")}>Low: {lowCount}</Text>
        </View>

        {/* Page Number Footer */}
        <Text
          style={tw("absolute bottom-8 left-10 right-10 text-center text-xs text-gray-400 border-t border-gray-200 pt-2")}
          fixed
          render={({ pageNumber, totalPages: tp }) =>
            `Page ${pageNumber} of ${tp} | Generated by DevSecShield - ${new Date().toLocaleString()}`
          }
        />
      </Page>

      {/* Vulnerability Pages - Max 3 per page */}
      {vulnerabilityChunks.map((chunk, chunkIndex) => (
        <Page key={`vuln-${chunkIndex}`} size="A4" style={tw("p-10")}>
          <View style={tw("mb-6")}>
            <Text style={tw("text-lg font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200")}>
              Vulnerabilities {chunkIndex === 0 ? "" : `(Continued)`}
            </Text>
            {chunk.map((vuln, index) => (
              <View key={`${chunkIndex}-${index}`} style={tw("mb-4 p-4 bg-gray-50 rounded border-l-4 border-red-500")}>
                <Text style={tw("text-base font-bold text-gray-800 mb-2")}>{vuln.name}</Text>
                <View style={tw("px-2 py-1 rounded text-xs font-bold mb-2 " + getSeverityClasses(vuln.severity))}>
                  <Text>{vuln.severity}</Text>
                </View>
                <Text style={tw("text-xs text-gray-600 mb-2 leading-relaxed")}>{vuln.description}</Text>
                
                {/* Code Snippet / Location */}
                {vuln.code_snippet_or_location && String(vuln.code_snippet_or_location).trim() !== "" && (
                  <View style={tw("mt-2 mb-2 p-2 bg-gray-100 rounded border border-gray-300")}>
                    <Text style={tw("text-xs font-bold text-gray-700 mb-1")}>Code Snippet / Location:</Text>
                    <Text style={tw("text-xs text-gray-600 leading-relaxed")}>
                      {String(vuln.code_snippet_or_location)}
                    </Text>
                  </View>
                )}
                
                {/* CVEs */}
                {vuln.cves && Array.isArray(vuln.cves) && vuln.cves.length > 0 && (
                  <View style={tw("mt-2 mb-2")}>
                    <Text style={tw("text-xs font-bold text-gray-700 mb-1")}>Related CVEs:</Text>
                    {vuln.cves.map((cve, cveIndex) => (
                      <View key={cveIndex} style={tw("mb-1")}>
                        <Text style={tw("text-xs text-gray-500")}>
                          • {cve?.cve_id || "N/A"}: {cve?.description || "No description available"}
                        </Text>
                      </View>
                    ))}
                  </View>
                )}
                
                {/* Recommended Fix */}
                {vuln.fix && String(vuln.fix).trim() !== "" && (
                  <View style={tw("mt-2 p-2 bg-green-50 rounded")}>
                    <Text style={tw("text-xs font-bold text-green-500 mb-1")}>Recommended Fix:</Text>
                    <Text style={tw("text-xs text-green-500 leading-relaxed")}>{String(vuln.fix)}</Text>
                  </View>
                )}
              </View>
            ))}
          </View>

          {/* Page Number Footer */}
          <Text
            style={tw("absolute bottom-8 left-10 right-10 text-center text-xs text-gray-400 border-t border-gray-200 pt-2")}
            fixed
            render={({ pageNumber, totalPages: tp }) =>
              `Page ${pageNumber} of ${tp} | Generated by DevSecShield - ${new Date().toLocaleString()}`
            }
          />
        </Page>
      ))}

    </Document>
  );
};

// Function to generate and download PDF
export const generateAndDownloadPDF = async (
  data: ExportResults,
  scanType: string = "Security Scan",
  scanTarget?: string | null,
  scanDate?: string
) => {
  try {
    const doc = <PDFDocument data={data} scanType={scanType} scanTarget={scanTarget} scanDate={scanDate} />;
    const blob = await pdf(doc).toBlob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    const fileName = scanType.includes("SAST") 
      ? `SAST_Scan_Report_${new Date().toISOString().split("T")[0]}.pdf`
      : scanType.includes("LLM")
      ? `LLM_Scan_Report_${new Date().toISOString().split("T")[0]}.pdf`
      : `Security_Scan_Report_${new Date().toISOString().split("T")[0]}.pdf`;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  } catch (error) {
    console.error("Error generating PDF:", error);
    throw error;
  }
};

