#!/usr/bin/env python3
"""
SecureLink Guardian - Benchmark Script
Performance benchmarking and profiling
"""

import time
import statistics
import json
import asyncio
from pathlib import Path
from typing import List, Dict
import requests
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

class Benchmark:
    """Benchmark runner"""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.results = []
    
    def load_test_urls(self) -> List[Dict]:
        """Load test URLs"""
        filepath = Path("tests/fixtures/test_urls.json")
        if filepath.exists():
            with open(filepath, 'r') as f:
                return json.load(f)
        return []
    
    def benchmark_scan(self, url: str) -> Dict:
        """Benchmark a single scan"""
        start_time = time.time()
        
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/scan",
                json={"url": url, "deep_scan": True},
                timeout=30
            )
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to ms
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'url': url,
                    'success': True,
                    'response_time': response_time,
                    'risk_score': data.get('risk_score', 0),
                    'verdict': data.get('verdict', 'unknown')
                }
            else:
                return {
                    'url': url,
                    'success': False,
                    'response_time': response_time,
                    'error': response.text
                }
        
        except Exception as e:
            end_time = time.time()
            return {
                'url': url,
                'success': False,
                'response_time': (end_time - start_time) * 1000,
                'error': str(e)
            }
    
    def run_benchmarks(self, iterations: int = 3):
        """Run benchmarks"""
        console.print("\n[bold blue]🔧 SecureLink Guardian - Performance Benchmark[/bold blue]\n")
        
        # Load test URLs
        test_urls = self.load_test_urls()
        if not test_urls:
            console.print("[red]❌ No test URLs found[/red]")
            return
        
        console.print(f"📊 Testing {len(test_urls)} URLs × {iterations} iterations\n")
        
        # Run benchmarks
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task("Running benchmarks...", total=len(test_urls) * iterations)
            
            for iteration in range(iterations):
                for test_url in test_urls:
                    result = self.benchmark_scan(test_url['url'])
                    result['iteration'] = iteration + 1
                    self.results.append(result)
                    progress.advance(task)
        
        # Analyze results
        self.analyze_results()
    
    def analyze_results(self):
        """Analyze benchmark results"""
        console.print("\n[bold green]📈 Benchmark Results[/bold green]\n")
        
        # Overall statistics
        successful = [r for r in self.results if r['success']]
        failed = [r for r in self.results if not r['success']]
        
        if not successful:
            console.print("[red]❌ All requests failed[/red]")
            return
        
        response_times = [r['response_time'] for r in successful]
        
        # Statistics table
        stats_table = Table(title="Overall Statistics")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        
        stats_table.add_row("Total Requests", str(len(self.results)))
        stats_table.add_row("Successful", str(len(successful)))
        stats_table.add_row("Failed", str(len(failed)))
        stats_table.add_row("Success Rate", f"{len(successful)/len(self.results)*100:.1f}%")
        
        console.print(stats_table)
        console.print()
        
        # Response time statistics
        time_table = Table(title="Response Time Statistics (ms)")
        time_table.add_column("Metric", style="cyan")
        time_table.add_column("Value", style="green")
        
        time_table.add_row("Mean", f"{statistics.mean(response_times):.2f}")
        time_table.add_row("Median", f"{statistics.median(response_times):.2f}")
        time_table.add_row("Min", f"{min(response_times):.2f}")
        time_table.add_row("Max", f"{max(response_times):.2f}")
        time_table.add_row("Std Dev", f"{statistics.stdev(response_times):.2f}")
        
        # Percentiles
        sorted_times = sorted(response_times)
        p50 = sorted_times[int(len(sorted_times) * 0.50)]
        p90 = sorted_times[int(len(sorted_times) * 0.90)]
        p95 = sorted_times[int(len(sorted_times) * 0.95)]
        p99 = sorted_times[int(len(sorted_times) * 0.99)]
        
        time_table.add_row("P50", f"{p50:.2f}")
        time_table.add_row("P90", f"{p90:.2f}")
        time_table.add_row("P95", f"{p95:.2f}")
        time_table.add_row("P99", f"{p99:.2f}")
        
        console.print(time_table)
        console.print()
        
        # Per-URL results
        url_table = Table(title="Per-URL Results")
        url_table.add_column("URL", style="cyan", no_wrap=False)
        url_table.add_column("Avg Time (ms)", style="green")
        url_table.add_column("Risk Score", style="yellow")
        url_table.add_column("Verdict", style="magenta")
        
        # Group by URL
        url_results = {}
        for result in successful:
            url = result['url']
            if url not in url_results:
                url_results[url] = []
            url_results[url].append(result)
        
        for url, results in url_results.items():
            avg_time = statistics.mean([r['response_time'] for r in results])
            avg_risk = statistics.mean([r['risk_score'] for r in results])
            verdict = results[0]['verdict']
            
            # Truncate URL if too long
            display_url = url if len(url) <= 40 else url[:37] + "..."
            
            url_table.add_row(
                display_url,
                f"{avg_time:.2f}",
                f"{avg_risk:.0f}",
                verdict
            )
        
        console.print(url_table)
        
        # Save results
        self.save_results()
    
    def save_results(self):
        """Save results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = Path(f"logs/benchmark_{timestamp}.json")
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        console.print(f"\n💾 Results saved to: {filepath}")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="SecureLink Guardian Benchmark")
    parser.add_argument("--url", default="http://localhost:5000", help="API base URL")
    parser.add_argument("--iterations", type=int, default=3, help="Number of iterations")
    
    args = parser.parse_args()
    
    # Check if server is running
    try:
        response = requests.get(f"{args.url}/api/v1/health", timeout=5)
        if response.status_code != 200:
            console.print(f"[red]❌ Server not healthy at {args.url}[/red]")
            return
    except Exception as e:
        console.print(f"[red]❌ Cannot connect to server at {args.url}[/red]")
        console.print(f"[red]   Error: {e}[/red]")
        return
    
    # Run benchmarks
    benchmark = Benchmark(args.url)
    benchmark.run_benchmarks(args.iterations)

if __name__ == "__main__":
    main()