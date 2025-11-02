from classes.FlowClassifier import FlowClassifier

def main():
    model_path = "models/classifier/xgb_clf_multiclass.pkl"
    anomaly_detector = "models/anomaly_detector/isolation_forest.pkl"

    classifier = FlowClassifier(model_path, anomaly_detector)
    classifier.start_capture()

if __name__ =="__main__":
    main()
