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

      this.setState({ ...this.state, [name]: type === "checkbox" ? checked : normalizedValue })
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
        e("h2", null, "Enter your API key to start using the App!"),
        e("div", null, [
          e("form", { onSubmit: this.handleSubmit, style: formStyle }, [

            // --- API Key Input ---
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

            // --- Enable batching Checkbox ---
            e("div", { style: checkboxContainerStyle }, [
              e("label", { style: checkboxLabelStyle }, [
                e("input", {
                  type: "checkbox",
                  name: "batching",
                  checked: this.state.batching,
                  onChange: this.handleChange,
                  style: checkboxInputStyle
                }),
                e("span", { style: checkboxTextStyle }, "Enable batching")
              ])
            ]),

            // --- Enable full local dump Checkbox ---
            e("div", { style: checkboxContainerStyle }, [
              e("label", { style: checkboxLabelStyle }, [
                e("input", {
                  type: "checkbox",
                  name: "local_dump",
                  checked: this.state.local_dump,
                  onChange: this.handleChange,
                  style: checkboxInputStyle
                }),
                e("span", { style: checkboxTextStyle }, "Enable full local dump")
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
                  disabled: !this.state.batching,
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
