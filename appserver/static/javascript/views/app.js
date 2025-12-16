import * as Setup from "./store_secret.js";

define(["react", "splunkjs/splunk"], function (react, splunk_js_sdk) {
  const e = react.createElement;

  class SetupPage extends react.Component {
    constructor(props) {
      super(props);
      this.state = {
        password: "",
        batching: false,
        batch_size: 10,
        local_dump: false,

        // UI helpers
        importFileName: "",
        saving: false,
        statusMessage: "",
        statusType: "", // "ok" | "error" | ""
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
            local_dump: settings.local_dump ?? false,
          });
        }
      } catch (error) {
        console.error("Failed to load existing CrowdSec settings:", error);
      }
    }

    handleChange(event) {
      const { name, type, checked, value } = event.target;
      const normalizedValue =
        name === "batch_size" ? parseInt(value, 10) || 10 : value;

      this.setState((prevState) => {
        const nextState = { ...prevState };

        if (name === "local_dump") {
          const enabled = type === "checkbox" ? checked : !!normalizedValue;
          nextState.local_dump = enabled;
          if (enabled) {
            nextState.batching = false;
          }
        } else if (name === "batching") {
          const enabled = type === "checkbox" ? checked : !!normalizedValue;
          nextState.batching = enabled;
          if (enabled) {
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
      if (!file) return;

      this.setState({
        importFileName: file.name,
        statusMessage: "",
        statusType: "",
      });

      try {
        const text = await file.text();
        const config = JSON.parse(text);

        const current = this.state;

        const importedLocalDump =
          typeof config.local_dump === "boolean" ? config.local_dump : current.local_dump;
        const importedBatching =
          typeof config.batching === "boolean" ? config.batching : current.batching;
        const importedBatchSize =
          typeof config.batch_size === "number" ? config.batch_size : current.batch_size;

        let finalLocalDump = importedLocalDump;
        let finalBatching = importedBatching;

        if (finalLocalDump && finalBatching) {
          // prefer local_dump and disable batching
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
        this.setState({
          statusMessage: "Invalid config file. Please provide a valid JSON file.",
          statusType: "error",
        });
        alert("Invalid config file. Please provide a valid JSON file.");
      } finally {
        // allow re-selecting the same file (some browsers won't trigger onChange otherwise)
        event.target.value = "";
      }
    }

    async handleSubmit(event) {
      event.preventDefault();

      this.setState({ saving: true, statusMessage: "", statusType: "" });

      try {
        await Setup.perform(splunk_js_sdk, this.state);
        this.setState({
          statusMessage: "Saved successfully.",
          statusType: "ok",
        });
      } catch (error) {
        console.error("Failed to save settings:", error);
        this.setState({
          statusMessage: "Save failed. Check the browser console / splunkd logs.",
          statusType: "error",
        });
      } finally {
        this.setState({ saving: false });
      }
    }

    render() {
      const formStyle = {
        maxWidth: "650px",
        padding: "20px",
        fontFamily: "Arial, sans-serif",
        backgroundColor: "#f9f9f9",
        borderRadius: "8px",
        border: "1px solid #ddd",
      };

      const sectionStyle = {
        padding: "16px",
        backgroundColor: "#fff",
        borderRadius: "8px",
        border: "1px solid #ddd",
        marginBottom: "16px",
      };

      const sectionTitleStyle = {
        margin: "0 0 10px 0",
        fontSize: "16px",
        fontWeight: "600",
        color: "#333",
      };

      const helperTextStyle = {
        marginBottom: "10px",
        color: "#555",
        fontSize: "13px",
        lineHeight: "18px",
      };

      const dividerStyle = {
        border: "none",
        borderTop: "1px solid #ddd",
        margin: "16px 0",
      };

      const apiKeyContainerStyle = {
        marginBottom: "20px",
      };

      const labelStyle = {
        display: "flex",
        alignItems: "center",
        gap: "12px",
        marginBottom: "0",
      };

      const labelTextStyle = {
        minWidth: "120px",
        fontWeight: "600",
        color: "#333",
      };

      const inputStyle = {
        flex: "1",
        padding: "8px 12px",
        borderRadius: "4px",
        border: "1px solid #bbb",
        fontSize: "14px",
        fontFamily: "Arial, sans-serif",
        minWidth: "200px",
      };

      const checkboxContainerStyle = {
        marginBottom: "16px",
      };

      const checkboxLabelStyle = {
        display: "flex",
        alignItems: "center",
        gap: "10px",
        cursor: "pointer",
        userSelect: "none",
        marginBottom: "0",
      };

      const checkboxInputStyle = {
        width: "18px",
        height: "18px",
        cursor: "pointer",
        flexShrink: 0,
      };

      const checkboxTextStyle = {
        fontSize: "14px",
        color: "#333",
        fontWeight: "400",
      };

      const selectContainerStyle = {
        marginBottom: "24px",
      };

      const selectInputStyle = {
        padding: "8px 12px",
        borderRadius: "4px",
        border: "1px solid #bbb",
        fontSize: "14px",
        fontFamily: "Arial, sans-serif",
        backgroundColor: "#fff",
        cursor: "pointer",
        marginLeft: "12px",
      };

      const buttonContainerStyle = {
        marginTop: "24px",
        paddingTop: "16px",
        borderTop: "1px solid #ddd",
        display: "flex",
        alignItems: "center",
        gap: "12px",
      };

      const submitButtonStyle = {
        padding: "10px 24px",
        backgroundColor: "#007bba",
        color: "#fff",
        border: "none",
        borderRadius: "4px",
        fontSize: "14px",
        fontWeight: "600",
        cursor: "pointer",
        transition: "background-color 0.3s ease",
        minWidth: "100px",
        opacity: this.state.saving ? 0.7 : 1,
      };

      const statusStyle = {
        padding: "8px 12px",
        borderRadius: "6px",
        fontSize: "13px",
        border: "1px solid #ddd",
        backgroundColor: this.state.statusType === "ok" ? "#eef7ee" : "#fff1f1",
        color: this.state.statusType === "ok" ? "#1b5e20" : "#8a1f1f",
        display: this.state.statusMessage ? "inline-block" : "none",
      };

      // File input: hidden input + label button
      const fileInputHiddenStyle = { display: "none" };

      const fileButtonStyle = {
        display: "inline-block",
        padding: "8px 14px",
        backgroundColor: "#f3f4f6",
        border: "1px solid #bbb",
        borderRadius: "6px",
        cursor: "pointer",
        fontSize: "14px",
        fontWeight: "600",
      };

      const fileNameStyle = {
        marginLeft: "10px",
        color: "#555",
        fontSize: "13px",
      };

      const headerStyle = {
        display: "flex",
        alignItems: "center",
        gap: "12px",
        marginBottom: "16px"
      };

      const logoStyle = { height: "34px" };

      return e("div", null, [
        e("div", null, [
          e("form", { onSubmit: this.handleSubmit, style: formStyle }, [
            e("div", { style: headerStyle }, [
              e("img", {
                src: "/static/app/crowdsec-splunk-app/img/crowdsec_logo.png",
                style: logoStyle,
                alt: "CrowdSec"
              }),
              e("div", { style: { fontSize: "18px", fontWeight: "600", color: "#333" } }, "CrowdSec Setup")
            ]),
            // --- Import configuration section ---
            e("div", { style: sectionStyle }, [
              e("h2", { style: sectionTitleStyle }, "Import configuration"),
              e(
                "div",
                { style: helperTextStyle },
                "Upload a JSON config file to pre-fill the form. You can still edit values before saving."
              ),
              e("div", { style: { marginBottom: "10px", fontSize: "13px" } }, [
                "Example: ",
                e(
                  "a",
                  {
                    href: "/static/app/crowdsec-splunk-app/data/config_example.json",
                    target: "_blank",
                    rel: "noreferrer",
                  },
                  "example config"
                ),
              ]),
              e("div", null, [
                e("input", {
                  id: "crowdsec-config-file",
                  type: "file",
                  accept: "application/json",
                  onChange: this.handleConfigImport,
                  style: fileInputHiddenStyle,
                }),
                e(
                  "label",
                  { htmlFor: "crowdsec-config-file", style: fileButtonStyle },
                  "Choose JSON file"
                ),
                e(
                  "span",
                  { style: fileNameStyle },
                  this.state.importFileName ? this.state.importFileName : "No file selected"
                ),
              ]),
            ]),

            e("hr", { style: dividerStyle }),

            // --- Manual setup section ---
            e("div", { style: sectionStyle }, [
              e("h2", { style: sectionTitleStyle }, "Manual setup"),
              e(
                "div",
                { style: helperTextStyle },
                "Enter your API key and select how the app should query CrowdSec (batching vs local dump)."
              ),

              // API Key Input
              e("div", { style: apiKeyContainerStyle }, [
                e("label", { style: labelStyle }, [
                  e("span", { style: labelTextStyle }, "API Key:"),
                  e("input", {
                    type: "password",
                    name: "password",
                    value: this.state.password,
                    placeholder: "Leave empty to keep existing key",
                    onChange: this.handleChange,
                    style: inputStyle,
                  }),
                ]),
              ]),

              // Enable full local dump Checkbox
              e("div", { style: checkboxContainerStyle }, [
                e("label", { style: checkboxLabelStyle }, [
                  e("input", {
                    type: "checkbox",
                    name: "local_dump",
                    checked: this.state.local_dump,
                    disabled: this.state.batching,
                    onChange: this.handleChange,
                    style: checkboxInputStyle,
                  }),
                  e("span", { style: checkboxTextStyle }, "Enable full local dump"),
                ]),
              ]),

              // Enable batching Checkbox
              e("div", { style: checkboxContainerStyle }, [
                e("label", { style: checkboxLabelStyle }, [
                  e("input", {
                    type: "checkbox",
                    name: "batching",
                    checked: this.state.batching,
                    disabled: this.state.local_dump,
                    onChange: this.handleChange,
                    style: checkboxInputStyle,
                  }),
                  e("span", { style: checkboxTextStyle }, "Enable batching"),
                ]),
              ]),

              // Batch size Dropdown
              e("div", { style: selectContainerStyle }, [
                e("label", { style: labelStyle }, [
                  e("span", { style: labelTextStyle }, "Batch size:"),
                  e(
                    "select",
                    {
                      name: "batch_size",
                      value: this.state.batch_size,
                      onChange: this.handleChange,
                      disabled: !this.state.batching || this.state.local_dump,
                      style: selectInputStyle,
                    },
                    [
                      e("option", { value: 10 }, "10"),
                      e("option", { value: 20 }, "20"),
                      e("option", { value: 50 }, "50"),
                      e("option", { value: 100 }, "100"),
                    ]
                  ),
                ]),
              ]),

              // Submit
              e("div", { style: buttonContainerStyle }, [
                e("input", {
                  type: "submit",
                  value: this.state.saving ? "Saving..." : "Submit",
                  style: submitButtonStyle,
                  disabled: this.state.saving,
                }),
                e("span", { style: statusStyle }, this.state.statusMessage),
              ]),
            ]),
          ]),
        ]),
      ]);
    }
  }

  return e(SetupPage);
});
