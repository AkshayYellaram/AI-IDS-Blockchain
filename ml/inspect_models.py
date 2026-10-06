import joblib
from pathlib import Path


MODEL_FILES = {
    "UNSW-NB15": "ml/ids_model.pkl",
    "CICIDS Random Forest": "ml/cicids_random_forest.pkl",
    "CICIDS Extra Trees": "ml/cicids_extra_trees.pkl",
    "CICIDS Gradient Boosting": "ml/cicids_gradient_boosting.pkl",
    "Isolation Forest": "ml/isolation_forest.pkl",
}


def inspect_model(name, path):
    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)
    print("File:", path)

    if not Path(path).exists():
        print("ERROR: file does not exist")
        return

    try:
        model = joblib.load(path)

        print("Type:", type(model))

        if hasattr(model, "named_steps"):
            print("\nPipeline steps:")
            for step_name, step in model.named_steps.items():
                print(f"  {step_name}: {type(step)}")

        if hasattr(model, "steps"):
            print("\nSteps:")
            for step_name, step in model.steps:
                print(f"  {step_name}: {type(step)}")

        if hasattr(model, "feature_names_in_"):
            print("\nFeature names:")
            print(list(model.feature_names_in_))

        if hasattr(model, "n_features_in_"):
            print("\nNumber of input features:")
            print(model.n_features_in_)

        if hasattr(model, "classes_"):
            print("\nClasses:")
            print(model.classes_)

        # Inspect preprocessing transformers
        if hasattr(model, "named_steps"):
            for step_name, step in model.named_steps.items():

                if hasattr(step, "transformers_"):
                    print(f"\nColumn transformers in '{step_name}':")

                    for transformer in step.transformers_:
                        print(" ", transformer)

                if hasattr(step, "feature_names_in_"):
                    print(
                        f"\n'{step_name}' feature_names_in_:"
                    )
                    print(list(step.feature_names_in_))

        print("\nModel loaded successfully.")

    except Exception as e:
        print("ERROR:", repr(e))


for name, path in MODEL_FILES.items():
    inspect_model(name, path)

print("\n" + "=" * 70)
print("MODEL INSPECTION COMPLETE")
print("=" * 70)