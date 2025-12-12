import * as Setup from "./store_secret.js";

define(["react", "splunkjs/splunk"], function (react, splunk_js_sdk) {
  const e = react.createElement;

  class SetupPage extends react.Component {
    constructor(props) {
      super(props);
      this.state = {
        password: '',
        batching: false,
        batch_size: 10,
        local_dump: false
      };

      this.handleChange = this.handleChange.bind(this);
      this.handleSubmit = this.handleSubmit.bind(this);
      this.handleConfigImport = this.handleConfigImport.bind(this);
    }

    async componentDidMount() {
      try {
        const settings = await Setup.fetchSettings(splunk_js_sdk);
        if (settings) {
          this.setState({
            batching: settings.batching ?? false,
            batch_size: settings.batch_size ?? 10,
          });
        }
      } catch (error) {
        console.error("Failed to load existing CrowdSec settings:", error);
      }
    }

    handleChange(event) {
      const { name, type, checked, value } = event.target;
      const normalizedValue = name === "batch_size" ? parseInt(value, 10) || 10 : value;

      this.setState(prevState => {
        const nextState = { ...prevState };

        if (name === "local_dump") {
          const enabled = type === "checkbox" ? checked : !!normalizedValue;
          nextState.local_dump = enabled;
          if (enabled) {
            // Disable batching if full local dump is enabled
            nextState.batching = false;
          }
        } else if (name === "batching") {
          const enabled = type === "checkbox" ? checked : !!normalizedValue;
          nextState.batching = enabled;
          if (enabled) {
            // Disable local dump if batching is enabled
            nextState.local_dump = false;
          }
        } else if (name === "batch_size") {
          nextState.batch_size = normalizedValue;
        } else {
          nextState[name] = type === "checkbox" ? checked : normalizedValue;
        }

        return nextState;
      });
    }

    async handleConfigImport(event) {
      const file = event.target.files[0];
      if (!file) {
        return;
      }

      try {
        const text = await file.text();
        const config = JSON.parse(text);

        // Start from current state
        const current = this.state;

        // Read raw values from config (or keep current if not provided)
        const importedLocalDump =
          typeof config.local_dump === "boolean" ? config.local_dump : current.local_dump;
        const importedBatching =
          typeof config.batching === "boolean" ? config.batching : current.batching;
        const importedBatchSize =
          typeof config.batch_size === "number" ? config.batch_size : current.batch_size;

        // Enforce mutual exclusion:
        // - If local_dump is true, force batching off.
        // - If batching is true and local_dump is false, keep as is.
        let finalLocalDump = importedLocalDump;
        let finalBatching = importedBatching;

        if (finalLocalDump && finalBatching) {
          // Decide which one wins; here we prefer local_dump and disable batching
          finalBatching = false;
        }

        this.setState({
          password: config.api_key ?? current.password,
          batching: finalBatching,
          batch_size: importedBatchSize,
          local_dump: finalLocalDump,
        });
      } catch (error) {
        console.error("Failed to import config file:", error);
        alert("Invalid config file. Please provide a valid JSON file.");
      }
    }

    async handleSubmit(event) {
      event.preventDefault();

      await Setup.perform(splunk_js_sdk, this.state)
    }
    render() {
      const formStyle = {
        maxWidth: '500px',
        padding: '20px',
        fontFamily: 'Arial, sans-serif',
        backgroundColor: '#f9f9f9',
        borderRadius: '8px',
        border: '1px solid #ddd'
      };

      const apiKeyContainerStyle = {
        marginBottom: '20px'
      };

      const labelStyle = {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        marginBottom: '0'
      };

      const labelTextStyle = {
        minWidth: '120px',
        fontWeight: '600',
        color: '#333'
      };

      const inputStyle = {
        flex: '1',
        padding: '8px 12px',
        borderRadius: '4px',
        border: '1px solid #bbb',
        fontSize: '14px',
        fontFamily: 'Arial, sans-serif',
        minWidth: '200px'
      };

      const checkboxContainerStyle = {
        marginBottom: '16px'
      };

      const checkboxLabelStyle = {
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        cursor: 'pointer',
        userSelect: 'none',
        marginBottom: '0'
      };

      const checkboxInputStyle = {
        width: '18px',
        height: '18px',
        cursor: 'pointer',
        flexShrink: 0
      };

      const checkboxTextStyle = {
        fontSize: '14px',
        color: '#333',
        fontWeight: '400'
      };

      const selectContainerStyle = {
        marginBottom: '24px'
      };

      const selectInputStyle = {
        padding: '8px 12px',
        borderRadius: '4px',
        border: '1px solid #bbb',
        fontSize: '14px',
        fontFamily: 'Arial, sans-serif',
        backgroundColor: '#fff',
        cursor: 'pointer',
        marginLeft: '12px'
      };

      const buttonContainerStyle = {
        marginTop: '24px',
        paddingTop: '16px',
        borderTop: '1px solid #ddd'
      };

      const submitButtonStyle = {
        padding: '10px 24px',
        backgroundColor: '#007bba',
        color: '#fff',
        border: 'none',
        borderRadius: '4px',
        fontSize: '14px',
        fontWeight: '600',
        cursor: 'pointer',
        transition: 'background-color 0.3s ease',
        minWidth: '100px'
      };

      return e("div", null, [
        e("div", null, [
          e("form", { onSubmit: this.handleSubmit, style: formStyle }, [
            e("div", { style: { marginBottom: '20px' } }, [
              e("span", { style: labelTextStyle }, "Import config:"),
              e("input", {
                type: "file",
                accept: "application/json",
                onChange: this.handleConfigImport,
                style: { marginLeft: '12px', display: 'inline-block' }
              })
            ]),
            // --- API Key Input ---
            e("h2", null, "Enter your API key to start using the App!"),
            e("div", { style: apiKeyContainerStyle }, [
              e("label", { style: labelStyle }, [
                e("span", { style: labelTextStyle }, "API Key:"),
                e("input", {
                  type: "text",
                  name: "password",
                  value: this.state.password,
                  placeholder: "Leave empty to keep existing key",
                  onChange: this.handleChange,
                  style: inputStyle
                })
              ])
            ]),

            // Enable full local dump Checkbox
            e("div", { style: checkboxContainerStyle }, [
              e("label", { style: checkboxLabelStyle }, [
                e("input", {
                  type: "checkbox",
                  name: "local_dump",
                  checked: this.state.local_dump,
                  disabled: this.state.batching,            // cannot enable local dump when batching is on
                  onChange: this.handleChange,
                  style: checkboxInputStyle
                }),
                e("span", { style: checkboxTextStyle }, "Enable full local dump")
              ])
            ]),

            // --- Enable batching Checkbox ---
            e("div", { style: checkboxContainerStyle }, [
              e("label", { style: checkboxLabelStyle }, [
                e("input", {
                  type: "checkbox",
                  name: "batching",
                  checked: this.state.batching,
                  disabled: this.state.local_dump,          // cannot enable batching when local_dump is on
                  onChange: this.handleChange,
                  style: checkboxInputStyle
                }),
                e("span", { style: checkboxTextStyle }, "Enable batching")
              ])
            ]),


            // --- Batch size Dropdown ---
            e("div", { style: selectContainerStyle }, [
              e("label", { style: labelStyle }, [
                e("span", { style: labelTextStyle }, "Batch size:"),
                e("select", {
                  name: "batch_size",
                  value: this.state.batch_size,
                  onChange: this.handleChange,
                  disabled: !this.state.batching || this.state.local_dump,  // only when batching on and no local dump
                  style: selectInputStyle
                }, [
                  e("option", { value: 10 }, "10"),
                  e("option", { value: 20 }, "20"),
                  e("option", { value: 50 }, "50"),
                  e("option", { value: 100 }, "100")
                ])
              ])
            ]),
            // --- Submit Button ---
            e("div", { style: buttonContainerStyle }, [
              e("input", { type: "submit", value: "Submit", style: submitButtonStyle })
            ])
          ])
        ])
      ]);
    }
  }

  return e(SetupPage);
});
