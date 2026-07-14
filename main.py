from agents.graph import graph

if __name__ == "__main__":
    result = graph.invoke(
        {
            "alert_path": "alerts/sample_alerts.json"
        }
    )

    print("\nPipeline completed successfully!")