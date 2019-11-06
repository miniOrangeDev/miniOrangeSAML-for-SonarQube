package com.miniorange.app.classes;

import java.io.Serializable;
import java.util.Map;

public class MoSAMLResponse
		implements Serializable
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private Map<String, String[]> attributes;
	private String nameId;
	private String sessionIndex;
	private String relayStateURL;

	public MoSAMLResponse(Map<String, String[]> attributes, String nameId, String sessionIndex, String relayStateURL)
	{
		this.attributes = attributes;
		this.nameId = nameId;
		this.sessionIndex = sessionIndex;
		this.relayStateURL = relayStateURL;
	}

	public Map<String, String[]> getAttributes()
	{
		return this.attributes;
	}

	public void setAttributes(Map<String, String[]> attributes)
	{
		this.attributes = attributes;
	}

	public String getNameId()
	{
		return this.nameId;
	}

	public void setNameId(String nameId)
	{
		this.nameId = nameId;
	}

	public String getRelayStateURL()
	{
		return this.relayStateURL;
	}

	public void setRelayStateURL(String relayStateURL)
	{
		this.relayStateURL = relayStateURL;
	}

	public String getSessionIndex()
	{
		return this.sessionIndex;
	}

	public void setSessionIndex(String sessionIndex)
	{
		this.sessionIndex = sessionIndex;
	}

	public String toString()
	{
		return "MoSAMLResponse{attributes=" + this.attributes + ", nameId=" + this.nameId + ", sessionIndex='" + this.sessionIndex + ", relayStateURL='" + this.relayStateURL + "}";
	}
}

